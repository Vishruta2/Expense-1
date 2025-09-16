# --- imports (consolidated) ---
import json
from contextlib import closing

from decimal import Decimal, InvalidOperation
import base64, re as _re

def D(x, default="0.00"):
    try:
        if x is None: return Decimal(default)
        if isinstance(x, (int, float, Decimal)): return Decimal(str(x))
        s = str(x).strip()
        if not s: return Decimal(default)
        return Decimal(s)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)

def b64bytes(s):
    """Accepts raw base64 (with or without padding) or data URLs like "data:image/png;base64,....".
    Returns bytes or None on failure. Also passes through bytes unchanged.
    """
    if not s:
        return None
    # Fast-path: already bytes
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    try:
        st = str(s).strip()
        # If it's a data URL, strip prefix
        m = _re.match(r'^data:[^;]+;base64,(.*)$', st, _re.IGNORECASE)
        if m:
            st = m.group(1)
        # Normalize whitespace and URL form quirks
        st = st.replace('\n', '').replace('\r', '').replace(' ', '+')
        # Add missing padding if needed
        missing = (-len(st)) % 4
        if missing:
            st += '=' * missing
        return base64.b64decode(st, validate=False)
    except Exception:
        return None

def _ok(data=None, status=200):
    return JsonResponse({"ok": True, "data": data or {}}, status=status)

def _err(msg, status=400):
    return JsonResponse({"ok": False, "error": msg}, status=status)

def _get_json_or_form(request):
    # supports multipart (FormData) or JSON
    ctype = (request.META.get("CONTENT_TYPE") or "").lower()
    if ctype.startswith("application/json"):
        try:
            return json.loads(request.body.decode("utf-8") or "{}"), {}
        except Exception:
            return {}, {}
    # multipart: normal fields in POST, files in FILES
    return request.POST.dict(), request.FILES

# optional: used by the bill-serving views
def _require_login(request):
    if not request.session.get("auth"):
        return redirect("/")
    return None




from contextlib import closing
from datetime import datetime, date as ddate
from decimal import Decimal, InvalidOperation
import json

from django.contrib.auth.hashers import check_password
from django.db import connection, transaction, IntegrityError
from django.http import (
    JsonResponse, HttpResponseNotAllowed, HttpResponse, HttpResponseNotFound
)
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET


# ---------------- helpers ----------------
def _ok(data=None, status=200):
    return JsonResponse({"ok": True, "data": data or {}}, status=status)

def _err(msg, status=400):
    return JsonResponse({"ok": False, "error": msg}, status=status)

def _json(request):
    ctype = (request.META.get("CONTENT_TYPE") or "").lower()
    if ctype.startswith("application/json"):
        try:
            return json.loads((request.body or b"").decode("utf-8") or "{}")
        except Exception:
            return {}
    return {k: v for k, v in request.POST.items()}

def _json_or_form(request):
    ctype = (request.META.get("CONTENT_TYPE") or "").lower()
    if ctype.startswith("application/json"):
        try:
            return json.loads((request.body or b"").decode("utf-8") or "{}"), None
        except Exception:
            return {}, None
    return {k: v for k, v in request.POST.items()}, request.FILES

def _next_id(table, col):
    with closing(connection.cursor()) as cur:
        cur.execute(f"SELECT COALESCE(MAX({col}),0)+1 FROM {table}")
        (n,) = cur.fetchone()
    return int(n or 1)


# ------------- pages / lookups -------------
def employee_dashboard(request):
    if not request.session.get("auth"):
        return redirect("/")
    return render(request, "dashboard.html", {"user": request.session["auth"]})

@require_GET
def suppliers_list(request):
    with connection.cursor() as cur:
        cur.execute("SELECT supplier_id, name FROM supplierdata ORDER BY name ASC")
        rows = cur.fetchall()
    return JsonResponse([{"supplier_id": r[0], "name": r[1]} for r in rows], safe=False)
@require_GET
def projects_list(request):
    """Return available work orders for voucher dropdowns.

    Previously this endpoint filtered on status='active', which resulted in
    empty dropdowns if data did not strictly use that value. To make the UI
    resilient, return all non-empty work order numbers sorted by project name.
    """
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT work_order_no, project_name
              FROM projects
             WHERE work_order_no IS NOT NULL AND TRIM(work_order_no) <> ''
             ORDER BY project_name ASC
            """
        )
        rows = cur.fetchall()
    data = [{"work_order_no": r[0], "project_name": r[1]} for r in rows]
    return JsonResponse(data, safe=False)
# @require_GET
# def projects_list(request):
#     with connection.cursor() as cur:
#         cur.execute("SELECT work_order_no FROM projects ORDER BY work_order_no ASC")
#         rows = cur.fetchall()
#     return JsonResponse([{"work_order_no": r[0]} for r in rows], safe=False)


# ---------------- auth ----------------
@csrf_exempt
def login_api(request):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    b = _json(request)
    username = (b.get("username") or "").strip()
    password = (b.get("password") or "")  # keep original
    if not username or not password.strip():
        return JsonResponse({"ok": False, "error": "username and password are required"}, status=400)

    with closing(connection.cursor()) as cur:
        # If your DB collation is case-insensitive this is fine; otherwise LOWER() both sides.
        cur.execute(
            "SELECT cred_id, role, password, emp_id FROM Credentials WHERE username=%s LIMIT 1",
            [username],
        )
        row = cur.fetchone()

    if not row:
        return JsonResponse({"ok": False, "error": "Invalid username or password"}, status=401)

    cred_id, role, db_password, emp_id = row
    # Robust password match: hashed OR plaintext, with leading/trailing spaces tolerated
    p_in  = password
    p_in_s = password.strip()
    dbp   = db_password or ""
    dbp_s = dbp.strip()

    valid = False
    try:
        # hashed check first (db can be hashed)
        valid = check_password(p_in, dbp) or check_password(p_in_s, dbp) \
                or check_password(p_in, dbp_s) or check_password(p_in_s, dbp_s)
    except Exception:
        pass

    # plaintext fallback (legacy)
    if not valid:
        valid = (p_in == dbp) or (p_in_s == dbp) or (p_in == dbp_s) or (p_in_s == dbp_s)

    if not valid:
        # keep it generic (don’t reveal which part failed)
        return JsonResponse({"ok": False, "error": "Invalid username or password"}, status=401)

    request.session["auth"] = {
        "cred_id": int(cred_id),
        "username": username,
        "role": role,
        "emp_id": int(emp_id),
    }
    return JsonResponse({"ok": True, "data": {"redirect": "/employee-dashboard/", "role": role, "emp_id": int(emp_id)}}, status=200)


@csrf_exempt
def logout_api(request):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    request.session.flush()
    return _ok({"logged_out": True})


# -------- voucher id: X-PV-001 (per-employee per-month) --------
def _safe_json_parse(raw):
    """Try hard to parse JSON coming from multipart forms."""
    if raw is None:
        return {}
    s = str(raw).strip()
    if not s:
        return {}
    # First try normal JSON
    try:
        return json.loads(s)
    except Exception:
        pass
    # Remove BOM and control chars
    s2 = s.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
    # Remove trailing commas before } or ]
    s2 = re.sub(r',\s*([}\]])', r'\1', s2)
    try:
        return json.loads(s2)
    except Exception:
        pass
    # Convert single quotes to double quotes ONLY if it looks like a flat JSON
    if s2.startswith('{') and s2.endswith('}'):
        s3 = re.sub(r"'", '"', s2)
        try:
            return json.loads(s3)
        except Exception:
            pass
    raise ValueError('Invalid JSON')

def _parse_voucher_json(request):
    # Detect content type
    ctype = (request.META.get("CONTENT_TYPE") or "").lower()

    # 1) Multipart/form-data: read fields from request.POST (not request.body)
    if ctype.startswith("multipart/"):
        # If a JSON blob is provided explicitly, parse it
        if request.POST.get("voucher_json") is not None:
            return _safe_json_parse(request.POST.get("voucher_json"))

        # Otherwise, synthesize a dict from regular form fields you already send
        d = request.POST.dict()
        return {
            # map to keys your view already supports
            "bill_date":     d.get("bill_date") or d.get("billdate") or "",
            # your UI’s “Date” is the upload/current date
            "upload_date":   d.get("date") or d.get("uploadate") or "",
            "work_order_no": d.get("work_order_no") or d.get("workordernumber") or "",
            "total_amount":  d.get("total_amount"),
            "purchase1":     {"description": d.get("description") or ""},
            "username":      d.get("username") or ((request.session.get("auth") or {}).get("username") or ""),
            "vouchertype":   d.get("voucher_type") or "purchase",
        }

    # 2) Application/json: parse normally
    if ctype.startswith("application/json"):
        try:
            return json.loads((request.body or b"").decode("utf-8") or "{}")
        except Exception:
            raise ValueError("Invalid JSON")

    # Fallback
    return {}

def _get_emp_id_from_request(request, username):
    try:
        auth = request.session.get('auth') or {}
        if auth.get('emp_id'):
            return int(auth['emp_id'])
    except Exception:
        pass
    if username:
        with connection.cursor() as cur:
            cur.execute("""                SELECT e.emp_id
                  FROM credentials c
                  JOIN employee e ON e.emp_id = c.emp_id
                 WHERE c.username = %s
                 LIMIT 1
            """, [username])
            row = cur.fetchone()
            if row: return int(row[0])
            cur.execute("""                SELECT emp_id FROM employee
                 WHERE name=%s OR email_id=%s
                 LIMIT 1
            """, [username, username])
            row = cur.fetchone()
            if row: return int(row[0])
    return None
def _manager_approve_seq_for(emp_id: int):
    """
    Return credentials.approve_seq for the reporting manager of the given emp_id.
    If nothing found, return None.
    """
    with connection.cursor() as cur:
        cur.execute("""
            SELECT c.approve_seq
            FROM employee e
            JOIN employee mgr ON mgr.emp_id = e.reporting_manager
            JOIN credentials c ON c.emp_id = mgr.emp_id
            WHERE e.emp_id = %s
            LIMIT 1
        """, [emp_id])
        row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else None
def _manager_chain(emp_id: int, max_levels: int = 4):
    """Follow employee.reporting_manager up to 4 levels; returns a list of manager emp_ids [lvl1, lvl2, ...]."""
    chain, seen, cur_emp = [], {emp_id}, emp_id
    with connection.cursor() as cur:
        for _ in range(max_levels):
            cur.execute("SELECT reporting_manager FROM employee WHERE emp_id=%s", [cur_emp])
            row = cur.fetchone()
            if not row or not row[0]: break
            mid = int(row[0])
            if mid in seen: break
            chain.append(mid)
            seen.add(mid)
            cur_emp = mid
    return chain

def _insert_voucher_status_row(voucher_id: str, submitter_emp_id: int):
    """Create the voucher_status row with approver names + ids; remarks left NULL."""
    ids = _manager_chain(submitter_emp_id, 4)
    # Fetch names for those ids
    names = {}
    if ids:
        ph = ",".join(["%s"] * len(ids))
        with connection.cursor() as cur:
            cur.execute(f"SELECT emp_id, name FROM employee WHERE emp_id IN ({ph})", ids)
            for eid, nm in cur.fetchall():
                names[int(eid)] = nm or ""
    a = (ids + [None, None, None, None])[:4]
    n = [names.get(i, None) if i else None for i in a]
    with connection.cursor() as cur:
        cur.execute("""
            INSERT INTO voucher_status
            (voucher_id,
             approver1, remarks1, approver1id,
             approver2, remarks2, approver2id,
             approver3, remarks3, approver3id,
             approver4, remarks4, approver4id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, [voucher_id,
              n[0], None, a[0],
              n[1], None, a[1],
              n[2], None, a[2],
              n[3], None, a[3]])

def _insert_payment_request_status_row(request_id: int, submitter_emp_id: int, initial_remarks: str = None):
    """Create the payment_request_status row with approver names + ids; optional initial remarks (request description)."""
    ids = _manager_chain(submitter_emp_id, 4)
    # Fetch names for those ids
    names = {}
    if ids:
        ph = ",".join(["%s"] * len(ids))
        with connection.cursor() as cur:
            cur.execute(f"SELECT emp_id, name FROM employee WHERE emp_id IN ({ph})", ids)
            for eid, nm in cur.fetchall():
                names[int(eid)] = nm or ""
    a = (ids + [None, None, None, None])[:4]
    n = [names.get(i, None) if i else None for i in a]
    with connection.cursor() as cur:
        cur.execute(
            """
            INSERT INTO payment_request_status
            (request_id,
             approver1, remarks1, approver1id,
             approver2, remarks2, approver2id,
             approver3, remarks3, approver3id,
             approver4, remarks4, approver4id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            [request_id,
             n[0], (initial_remarks or None), a[0],
             n[1], None, a[1],
             n[2], None, a[2],
             n[3], None, a[3]]
        )

def _generate_payment_request_code(emp_id: int, ref_date: str):
    """Generate PR code like AA-PR-NNNMMYY based on employee initials and month of ref_date (YYYY-MM-DD)."""
    # initials from employee.name
    with connection.cursor() as cur:
        cur.execute("SELECT name FROM employee WHERE emp_id=%s", [emp_id])
        row = cur.fetchone()
    nm = (row[0] or '').strip().upper() if row else ''
    initials = (nm[:2] if len(nm) >= 2 else (nm[:1] + 'X')).upper() or 'XX'
    # derive ym and mmyy
    from datetime import datetime as _dt
    y = m = None
    try:
        d = _dt.strptime((ref_date or '')[:10], '%Y-%m-%d').date()
        y = d.year; m = d.month
    except Exception:
        pass
    ym = f"{y:04d}-{m:02d}" if (y and m) else (ref_date or '')[:7]
    mmyy = (f"{m:02d}{str(y)[-2:]}" if (y and m) else _dt.now().strftime('%m%y'))
    # sequence: count payment_request rows for this emp_id in this month
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM payment_request pr
            JOIN employee e ON e.emp_id = pr.emp_id
            WHERE pr.emp_id=%s AND DATE_FORMAT(CURDATE(),'%%Y-%%m')=%s
            """,
            [emp_id, ym]
        )
        (n,) = cur.fetchone() or (0,)
    return f"{initials}-PR-{(n+1):03d}{mmyy}"

@csrf_exempt
def api_payment_request_create(request):
    """Create a payment request. Fields: work_order_no, purpose(Advance|Purchase|Settlement), amount, description(>=50 chars).
    Stores into payment_request (approved_amount=0 initially) and initializes payment_request_status approvers.
    The description and work order are saved into remarks1 for traceability.
    """
    if request.method != 'POST':
        return _err('Only POST allowed', 405)
    body = {}
    try:
        ctype = (request.META.get('CONTENT_TYPE') or '').lower()
        if ctype.startswith('application/json'):
            body = json.loads((request.body or b'').decode('utf-8') or '{}')
        else:
            body = {k: v for k, v in request.POST.items()}
    except Exception:
        body = {}

    username = (body.get('username') or '').strip()
    emp_id = _get_emp_id_from_request(request, username)
    if emp_id is None:
        return _err('Employee not found or not logged in.', 401)

    wo = (body.get('work_order_no') or body.get('workordernumber') or '').strip()
    purpose = (body.get('purpose') or body.get('particulars') or '').strip().title()
    if purpose not in ('Advance', 'Purchase', 'Settlement'):
        return _err('purpose must be Advance, Purchase, or Settlement', 400)
    amt_raw = body.get('amount') or body.get('request_amount')
    try:
        request_amount = float(amt_raw)
    except Exception:
        request_amount = 0.0
    desc = (body.get('description') or body.get('remarks') or '').strip()
    if len(desc) < 50:
        return _err('Description must be at least 50 characters.', 400)

    with connection.cursor() as cur:
        cur.execute(
            """
            INSERT INTO payment_request (emp_id, purpose, request_amount, approved_amount)
            VALUES (%s,%s,%s,%s)
            """,
            [emp_id, purpose, request_amount, 0.0]
        )
        try:
            req_id = int(getattr(cur, 'lastrowid', 0) or 0)
        except Exception:
            req_id = 0
        if not req_id:
            # fallback
            cur.execute("SELECT MAX(request_id) FROM payment_request WHERE emp_id=%s", [emp_id])
            req_id = int(cur.fetchone()[0] or 0)

    # Initialize approver chain with initial remarks including WO no
    initial_remarks = (f"WO: {wo} | "+desc) if wo else desc
    _insert_payment_request_status_row(req_id, emp_id, initial_remarks)
    # Generate display code similar to voucher id
    from datetime import date as _d
    pr_code = _generate_payment_request_code(emp_id, _d.today().isoformat())
    return _ok({"request_id": req_id, "request_no": pr_code, "status": "created"}, status=201)

@require_GET
def api_payment_request_my_list(request):
    """List payment requests created by the logged-in employee."""
    auth = request.session.get('auth') or {}
    emp_id = auth.get('emp_id')
    if not emp_id:
        return _err('Not logged in', 401)
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT pr.request_id, pr.purpose, COALESCE(pr.request_amount,0), COALESCE(pr.approved_amount,0),
                   prs.approver1, prs.remarks1, prs.approver2, prs.remarks2, prs.approver3, prs.remarks3, prs.approver4, prs.remarks4,
                   e.name
              FROM payment_request pr
              JOIN payment_request_status prs ON prs.request_id = pr.request_id
              JOIN employee e ON e.emp_id = pr.emp_id
             WHERE pr.emp_id=%s
             ORDER BY pr.request_id DESC
            """,
            [emp_id]
        )
        rows = cur.fetchall()
    from datetime import date as _d
    today = _d.today().isoformat()
    # derive initials once
    emp_name = rows[0][12] if rows else ''
    nm = (emp_name or '').strip().upper()
    initials = (nm[:2] if len(nm) >= 2 else (nm[:1] + 'X')).upper() or 'XX'
    mmyy = _d.today().strftime('%m%y')
    data = []
    for idx, r in enumerate(rows, start=1):
        rid = int(r[0]); purpose = r[1] or ''; req_amt = float(r[2] or 0); appr_amt = float(r[3] or 0)
        claim_no = f"{initials}-PR-{idx:03d}{mmyy}"
        data.append({
            'request_id': rid,
            'claim_no': claim_no,
            'date': today,  # display only
            'purpose': purpose,
            'request_amount': req_amt,
            'approved_amount': appr_amt,
            'manager': r[12] or '',
            'approver1': r[4], 'remarks1': r[5],
            'approver2': r[6], 'remarks2': r[7],
            'approver3': r[8], 'remarks3': r[9],
            'approver4': r[10], 'remarks4': r[11],
        })
    return JsonResponse(data, safe=False)

@require_GET
def api_payment_request_pending_list(request):
    """List payment requests currently assigned to the logged-in approver (next pending approverN is this emp)."""
    auth = request.session.get('auth') or {}
    approver_emp_id = auth.get('emp_id')
    if not approver_emp_id:
        return _err('Not logged in', 401)
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT pr.request_id,
                   pr.purpose,
                   COALESCE(pr.request_amount,0) AS request_amount,
                   COALESCE(pr.approved_amount,0) AS approved_amount,
                   e.name AS employee_name,
                   prs.approver1, prs.remarks1, prs.approver1id,
                   prs.approver2, prs.remarks2, prs.approver2id,
                   prs.approver3, prs.remarks3, prs.approver3id,
                   prs.approver4, prs.remarks4, prs.approver4id
              FROM payment_request pr
              JOIN employee e ON e.emp_id = pr.emp_id
              JOIN payment_request_status prs ON prs.request_id = pr.request_id
            """
        )
        base = cur.fetchall()
    out = []
    for r in base:
        # determine current approver id (first approverN that is NULL)
        seq = None
        for i in range(1,5):
            appr = r[6 + (i-1)*3]  # approverN value
            if appr in (None, ''):
                seq = i
                break
        if seq is None:
            continue  # all decided
        appr_id = r[8 + (seq-1)*3]  # approverNid
        if appr_id != approver_emp_id:
            continue
        out.append({
            'request_id': int(r[0]),
            'purpose': r[1] or '',
            'request_amount': float(r[2] or 0),
            'approved_amount': float(r[3] or 0),
            'employee_name': r[4] or '',
            'stage': seq,
            'is_final': (seq == max([i for i in range(1,5) if r[8 + (i-1)*3] is not None] or [seq])),
        })
    return JsonResponse(out, safe=False)

@csrf_exempt
def api_payment_request_decision(request):
    """Approve/Reject a pending payment request assigned to current approver.
    JSON: { request_id, decision: 'approve'|'reject', remarks?, approved_amount?, release_date? }
    On final approval, updates payment_request.approved_amount and inserts payment_release_status row.
    """
    if request.method != 'POST':
        return _err('Only POST allowed', 405)
    try:
        body = json.loads((request.body or b'').decode('utf-8') or '{}')
    except Exception:
        body = {}
    req_id = body.get('request_id')
    decision = (body.get('decision') or '').strip().lower()
    remarks = (body.get('remarks') or '').strip()
    if not req_id:
        return _err('request_id is required', 400)
    if decision not in ('approve','reject'):
        return _err('decision must be "approve" or "reject".', 400)
    auth = request.session.get('auth') or {}
    emp_id = auth.get('emp_id')
    if not emp_id:
        return _err('Not logged in', 401)

    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT pr.emp_id,
                   prs.approver1, prs.remarks1, prs.approver1id,
                   prs.approver2, prs.remarks2, prs.approver2id,
                   prs.approver3, prs.remarks3, prs.approver3id,
                   prs.approver4, prs.remarks4, prs.approver4id
              FROM payment_request pr
              JOIN payment_request_status prs ON prs.request_id = pr.request_id
             WHERE pr.request_id=%s
            """,
            [req_id]
        )
        row = cur.fetchone()
    if not row:
        return _err('Request not found', 404)

    # Find current stage and confirm approver matches
    seq = None
    appr_ids = {1: row[3], 2: row[6], 3: row[9], 4: row[12]}
    appr_vals = {1: row[1], 2: row[4], 3: row[7], 4: row[10]}
    last_seq = max([i for i,v in appr_ids.items() if v is not None] or [1])
    for i in range(1,5):
        if appr_vals[i] in (None, ''):
            seq = i
            break
    if seq is None:
        return _err('No pending stage for this request.', 409)
    if appr_ids.get(seq) != emp_id:
        return _err('You are not the assigned approver for this stage.', 403)

    # Persist decision
    with connection.cursor() as cur:
        if decision == 'approve':
            cur.execute(f"UPDATE payment_request_status SET approver{seq}=%s WHERE request_id=%s", ["1", req_id])
            if seq == last_seq:
                # final approver: require approved_amount and release_date inputs
                try:
                    approved_amount = float(body.get('approved_amount'))
                except Exception:
                    return _err('approved_amount is required and must be a number for final approval.', 400)
                release_date = (body.get('release_date') or '').strip()
                if not release_date:
                    return _err('release_date is required for final approval.', 400)
                # update payment_request.approved_amount
                cur.execute("UPDATE payment_request SET approved_amount=%s WHERE request_id=%s", [approved_amount, req_id])
                # insert into payment_release_status
                cur.execute(
                    """
                    INSERT INTO payment_release_status (request_id, released_amount, release_date, remarks)
                    VALUES (%s,%s,%s,%s)
                    """,
                    [req_id, approved_amount, release_date, (remarks or None)]
                )
        else:
            # reject: require remarks length
            if len(remarks) < 50:
                return _err('Remarks must be at least 50 characters to reject.', 400)
            cur.execute(f"UPDATE payment_request_status SET approver{seq}=%s, remarks{seq}=%s WHERE request_id=%s", ["0", remarks, req_id])
            # record in payment_release_status with zero released amount
            from datetime import date as _d
            cur.execute(
                """
                INSERT INTO payment_release_status (request_id, released_amount, release_date, remarks)
                VALUES (%s,%s,%s,%s)
                """,
                [req_id, 0.0, _d.today().isoformat(), remarks]
            )

    return _ok({"request_id": int(req_id), "decision": decision, "stage": seq})

# ---------------- Admin Maintenance ----------------
from django.views.decorators.http import require_http_methods

def _require_admin(request):
    auth = request.session.get('auth') or {}
    role = (auth.get('role') or '').lower()
    if not auth:
        return False
    return ('admin' in role)

@require_GET
def api_admin_department_list(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    with connection.cursor() as cur:
        cur.execute("SELECT dept_id, dept_name FROM department ORDER BY dept_name ASC")
        rows = cur.fetchall()
    data = []
    for dept_id, name in rows:
        try:
            dept_id_val = int(dept_id)
        except Exception:
            dept_id_val = None
        data.append({
            "dept_id": dept_id_val,
            "dept_name": name or "",
        })
    return JsonResponse(data, safe=False)

@require_GET
def api_admin_employee_list(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT e.emp_id, e.name, e.age, e.address, e.contact, e.email_id,
                   e.dept_id, e.reporting_manager, e.authority,
                   c.cred_id, c.username, c.role, c.approve_seq
              FROM employee e
         LEFT JOIN credentials c ON c.emp_id = e.emp_id
             ORDER BY e.name ASC
            """
        )
        rows = cur.fetchall()
    data = []
    for row in rows:
        emp_id = int(row[0]) if row[0] is not None else None
        age = int(row[2]) if row[2] is not None else None
        contact = str(row[4]) if row[4] is not None else ""
        dept_id = int(row[6]) if row[6] is not None else None
        reporting_manager = int(row[7]) if row[7] is not None else None
        cred_id = int(row[9]) if row[9] is not None else None
        approve_seq = int(row[12]) if row[12] is not None else 0
        data.append({
            "emp_id": emp_id,
            "name": row[1] or "",
            "age": age,
            "address": row[3] or "",
            "contact": contact,
            "email_id": row[5] or "",
            "dept_id": dept_id,
            "reporting_manager": reporting_manager,
            "authority": row[8] or "",
            "credential": {
                "cred_id": cred_id,
                "username": row[10] or "",
                "role": row[11] or "",
                "approve_seq": approve_seq,
            },
        })
    return JsonResponse(data, safe=False)

@require_GET
def api_admin_credentials_list(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT cred_id, role, username, emp_id, approve_seq
              FROM credentials
             ORDER BY username ASC
            """
        )
        rows = cur.fetchall()
    data = []
    for row in rows:
        cred_id = int(row[0]) if row[0] is not None else None
        emp_id = int(row[3]) if row[3] is not None else None
        approve_seq = int(row[4]) if row[4] is not None else 0
        data.append({
            "cred_id": cred_id,
            "role": row[1] or "",
            "username": row[2] or "",
            "emp_id": emp_id,
            "approve_seq": approve_seq,
        })
    return JsonResponse(data, safe=False)

@csrf_exempt
@require_http_methods(["POST"])
def api_admin_credentials_upsert(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    body = _json(request)

    def s(key):
        v = body.get(key)
        return ("" if v is None else str(v)).strip()

    def n(key):
        try:
            return int(body.get(key)) if body.get(key) not in (None, "", []) else None
        except Exception:
            return None

    cred_id = n('cred_id')
    emp_id = n('emp_id')
    username = s('username')
    raw_password = body.get('password')
    password = "" if raw_password is None else str(raw_password)
    password_clean = password.strip()
    role = s('role') or 'Employee'
    approve_seq = n('approve_seq')
    if approve_seq is None:
        approve_seq = 0

    if not username:
        return _err('username is required', 400)
    if not emp_id:
        return _err('emp_id is required', 400)
    if not cred_id and not password_clean:
        return _err('password is required when adding credentials', 400)

    try:
        with connection.cursor() as cur:
            if cred_id:
                if password_clean:
                    cur.execute(
                        """
                        UPDATE credentials
                           SET role=%s, username=%s, password=%s, emp_id=%s, approve_seq=%s
                         WHERE cred_id=%s
                        """,
                        [role, username, password_clean, emp_id, approve_seq, cred_id],
                    )
                else:
                    cur.execute(
                        """
                        UPDATE credentials
                           SET role=%s, username=%s, emp_id=%s, approve_seq=%s
                         WHERE cred_id=%s
                        """,
                        [role, username, emp_id, approve_seq, cred_id],
                    )
            else:
                new_id = _next_id('credentials', 'cred_id')
                cur.execute(
                    """
                    INSERT INTO credentials (cred_id, role, username, password, emp_id, approve_seq)
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    [new_id, role, username, password_clean, emp_id, approve_seq],
                )
                cred_id = new_id
        return _ok({"cred_id": int(cred_id)})
    except Exception as e:
        return _err(f"DB error: {e}", 500)

@csrf_exempt
@require_http_methods(["POST"])
def api_admin_employee_upsert(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    b = _json(request)
    def s(k):
        v = b.get(k); return ("" if v is None else str(v)).strip()
    def n(k):
        try: return int(b.get(k)) if b.get(k) not in (None, "", []) else None
        except Exception: return None
    emp_id = n('emp_id')
    name = s('name'); age = n('age'); address = s('address') or None
    try:
        contact = int(b.get('contact')) if b.get('contact') not in (None, "", []) else None
    except Exception:
        contact = None
    email_id = s('email_id') or None
    dept_id = n('dept_id'); reporting_manager = n('reporting_manager'); authority = s('authority') or None
    username = s('username'); password = s('password'); role = s('role') or 'EMPLOYEE'; approve_seq = n('approve_seq') or 0
    try:
        with connection.cursor() as cur:
            if emp_id:
                cur.execute(
                    """
                    UPDATE employee SET name=%s, age=%s, address=%s, contact=%s, email_id=%s, dept_id=%s, reporting_manager=%s, authority=%s
                    WHERE emp_id=%s
                    """,
                    [name, age, address, contact, email_id, dept_id, reporting_manager, authority, emp_id]
                )
            else:
                emp_id = _next_id('employee','emp_id')
                cur.execute(
                    """
                    INSERT INTO employee (emp_id, name, age, address, contact, email_id, dept_id, reporting_manager, authority)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    [emp_id, name, age, address, contact, email_id, dept_id, reporting_manager, authority]
                )
            # upsert credentials
            cur.execute("SELECT cred_id FROM credentials WHERE emp_id=%s LIMIT 1", [emp_id])
            row = cur.fetchone()
            if row:
                cred_id = int(row[0])
                set_pwd = ", password=%s" if password else ""
                sql = f"UPDATE credentials SET role=%s, username=%s{set_pwd}, approve_seq=%s WHERE cred_id=%s"
                params = [role, username, approve_seq, cred_id] if not password else [role, username, password, approve_seq, cred_id]
                cur.execute(sql, params)
            else:
                cur.execute(
                    """
                    INSERT INTO credentials (role, username, password, emp_id, approve_seq)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    [role, username, password, emp_id, approve_seq]
                )
        return _ok({"emp_id": emp_id})
    except Exception as e:
        return _err(f"DB error: {e}", 500)

@csrf_exempt
@require_http_methods(["POST"])
def api_master_travel_upsert(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    b = _json(request)
    def s(k):
        v = b.get(k); return ("" if v is None else str(v)).strip()
    def n(k):
        try: return int(b.get(k)) if b.get(k) not in (None, "", []) else None
        except Exception: return None
    tid = n('travelmaster_id')
    authoriser = s('visit_authoriser_name')
    food_per_day = s('food_per_day') or '0.00'
    status = n('status') or 1
    try:
        with connection.cursor() as cur:
            if tid:
                cur.execute(
                    "UPDATE master_travel SET visit_authoriser_name=%s, food_per_day=%s, status=%s WHERE travelmaster_id=%s",
                    [authoriser or None, food_per_day, status, tid]
                )
                return _ok({"travelmaster_id": tid, "updated": True})
            else:
                new_id = _next_id('master_travel','travelmaster_id')
                cur.execute(
                    "INSERT INTO master_travel (travelmaster_id, visit_authoriser_name, food_per_day, status) VALUES (%s,%s,%s,%s)",
                    [new_id, authoriser or None, food_per_day, status]
                )
                return _ok({"travelmaster_id": new_id, "updated": False}, 201)
    except Exception as e:
        return _err(f"DB error: {e}", 500)

@csrf_exempt
@require_http_methods(["POST"])
def api_master_transport_mode_upsert(request):
    if not _require_admin(request):
        return _err('Forbidden', 403)
    b = _json(request)
    def s(k):
        v = b.get(k); return ("" if v is None else str(v)).strip()
    def n(k):
        try: return int(b.get(k)) if b.get(k) not in (None, "", []) else None
        except Exception: return None
    mode_id = n('mode_id')
    mode = s('mode_of_transport')
    uom = s('UOM') or None
    fixed_status = 1 if str(b.get('fixed_status')).strip() in ('1','true','True','yes') else 0
    price = s('price') or '0.00'
    try:
        with connection.cursor() as cur:
            if mode_id:
                cur.execute(
                    "UPDATE master_transport_mode SET mode_of_transport=%s, UOM=%s, fixed_status=%s, price=%s WHERE mode_id=%s",
                    [mode, uom, fixed_status, price, mode_id]
                )
                return _ok({"mode_id": mode_id, "updated": True})
            else:
                new_id = _next_id('master_transport_mode','mode_id')
                cur.execute(
                    "INSERT INTO master_transport_mode (mode_id, mode_of_transport, UOM, fixed_status, price) VALUES (%s,%s,%s,%s,%s)",
                    [new_id, mode, uom, fixed_status, price]
                )
                return _ok({"mode_id": new_id, "updated": False}, 201)
    except Exception as e:
        return _err(f"DB error: {e}", 500)

def _normalize_date(s):
    if not s: return ''
    s = s.strip()
    for fmt in ('%Y-%m-%d','%d-%m-%Y'):
        try: return datetime.strptime(s, fmt).date().isoformat()
        except ValueError: continue
    return s

def _voucher_prefix(vtype):
    vtype = (vtype or '').upper()
    return {'PURCHASE':'PV','TRAVEL':'TV','EXPENSE':'EV'}.get(vtype,'VX')

def _generate_voucher_id(emp_id, upload_date, vtype):
    """
    Format: AA-<TYPE>-NNNMMYY where:
      - AA: first two letters of employee name (uppercased; pad with X)
      - TYPE: PV/TV/EV
      - NNN: sequence for that employee+type within the month (001..)
      - MMYY: month+year from upload_date (e.g., 0925)
    """
    with connection.cursor() as cur:
        cur.execute("SELECT name FROM employee WHERE emp_id=%s", [emp_id])
        row = cur.fetchone()
    nm = (row[0] or '').strip().upper() if row else ''
    initials = (nm[:2] if len(nm) >= 2 else (nm[:1] + 'X')).upper() or 'XX'

    # derive YM (YYYY-MM) and mmyy from upload_date
    y = m = None
    try:
        d = datetime.strptime((upload_date or '')[:10], '%Y-%m-%d').date()
        y = d.year; m = d.month
    except Exception:
        # fallback: try DD-MM-YYYY
        try:
            d = datetime.strptime((upload_date or '')[:10], '%d-%m-%Y').date()
            y = d.year; m = d.month
        except Exception:
            pass
    ym = f"{y:04d}-{m:02d}" if (y and m) else (upload_date or '')[:7]
    mmyy = (f"{m:02d}{str(y)[-2:]}" if (y and m) else datetime.now().strftime('%m%y'))

    with connection.cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) FROM voucher
             WHERE emp_id=%s AND UPPER(voucher_type)=%s
               AND DATE_FORMAT(upload_date,'%%Y-%%m')=%s
        """, [emp_id, (vtype or '').upper(), ym])
        (n,) = cur.fetchone() or (0,)
    return f"{initials}-{_voucher_prefix(vtype)}-{(n+1):03d}{mmyy}"

@csrf_exempt
def api_create_purchase_voucher(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    try:
        b = _parse_voucher_json(request)
    except ValueError as e:
        return _err(str(e), 400)

    bill_date   = _normalize_date((b.get('billdate') or b.get('bill_date') or '').strip())
    upload_date = _normalize_date((b.get('uploadate') or b.get('upload_date') or '').strip())
    work_order  = (b.get('workordernumber') or b.get('work_order_no') or '').strip()
    vtype       = (b.get('vouchertype') or 'purchase').strip()
    username    = (b.get('username') or '').strip()
    total_amt_raw = b.get('total_amount')

    try:
        total_amt = float(total_amt_raw) if str(total_amt_raw).strip() != '' else None
    except Exception:
        total_amt = None

    if not bill_date or not upload_date or not work_order or total_amt is None:
        return _err('billdate, uploadate, workordernumber, total_amount are required', 400)

    desc = ((b.get('purchase1') or {}).get('description') or '').strip()
    bill_file = request.FILES.get('bill')
    if not bill_file:
        return _err('Bill file is required for purchase vouchers.', 400)

    emp_id = _get_emp_id_from_request(request, username)
    if emp_id is None:
        return _err('Employee not found or not logged in', 401)

    voucher_id = _generate_voucher_id(emp_id, upload_date, vtype)
    status = _manager_approve_seq_for(emp_id)

    try:
        with transaction.atomic():
            with connection.cursor() as cur:
                cur.execute(
                    """INSERT INTO voucher (voucher_id, work_order_no, upload_date, expense_date, voucher_type, total_amount, emp_id,status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,[voucher_id, work_order, upload_date, bill_date, vtype, total_amt, emp_id, status]
                )
                cur.execute(
                    """                    INSERT INTO purchase (voucher_id, description, bill_photo)
                    VALUES (%s,%s,%s)
                    """,
                    [voucher_id, desc, bill_file.read() if bill_file else None]
                )
                _insert_voucher_status_row(voucher_id, emp_id)
    except Exception as e:
        return _err(f'Database error: {e}', 500)

    return _ok({'voucher_id': voucher_id, 'total_amount': total_amt, 'description': desc}, status=201)

# ------------- bill file serving -------------
def _require_login(request):
    if not request.session.get("auth"):
        return redirect("/")
    return None

def _guess_mime(data: bytes) -> str:
    if not data: return "application/octet-stream"
    if data.startswith(b"%PDF-"): return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"): return "image/png"
    if data.startswith(b"\xff\xd8"): return "image/jpeg"
    if data.startswith(b"GIF8"): return "image/gif"
    if data[:4] == b"RIFF" and b"WEBP" in data[:16]: return "image/webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"): return "image/tiff"
    return "application/octet-stream"

def serve_purchase_bill_by_voucher(request, voucher_id: str):
    guard = _require_login(request)
    if guard: return guard
    with closing(connection.cursor()) as cur:
        cur.execute("SELECT bill_photo FROM purchase WHERE voucher_id=%s LIMIT 1", [voucher_id])
        row = cur.fetchone()
    if not row or row[0] is None:
        return HttpResponseNotFound("No bill found for this voucher.")
    data = bytes(row[0]); ctype = _guess_mime(data)
    resp = HttpResponse(data, content_type=ctype)
    disp = "inline" if (ctype == "application/pdf" or ctype.startswith("image/")) else "attachment"
    resp["Content-Disposition"] = f'{disp}; filename="bill_{voucher_id}.{ctype.split("/")[-1]}"'
    return resp

def serve_purchase_bill_by_id(request, purchase_id: int):
    guard = _require_login(request)
    if guard: return guard
    with closing(connection.cursor()) as cur:
        cur.execute("SELECT bill_photo FROM purchase WHERE purchase_id=%s LIMIT 1", [purchase_id])
        row = cur.fetchone()
    if not row or row[0] is None:
        return HttpResponseNotFound("No bill found for this purchase.")
    data = bytes(row[0]); ctype = _guess_mime(data)
    resp = HttpResponse(data, content_type=ctype)
    disp = "inline" if (ctype == "application/pdf" or ctype.startswith("image/")) else "attachment"
    resp["Content-Disposition"] = f'{disp}; filename="bill_{purchase_id}.{ctype.split("/")[-1]}"'
    return resp

# --- Generic file serving for other voucher sections ---
def _serve_blob(sql: str, param=None):
    guard = None
    def _login_guard(req):
        if not req.session.get("auth"):
            return redirect("/")
        return None
    # using inner function so we don't duplicate code
    def handler(request, id_val=None, **kwargs):
        g = _login_guard(request)
        if g: return g
        # Support Django passing named URL kwargs
        if id_val is None:
            if param and param in kwargs:
                id_val = kwargs.get(param)
            elif kwargs:
                # take the first value
                try:
                    id_val = list(kwargs.values())[0]
                except Exception:
                    id_val = None
        if id_val is None:
            return HttpResponseNotFound("No file found.")
        with closing(connection.cursor()) as cur:
            cur.execute(sql, [id_val])
            row = cur.fetchone()
        if not row or row[0] is None:
            return HttpResponseNotFound("No file found.")
        data = bytes(row[0]); ctype = _guess_mime(data)
        resp = HttpResponse(data, content_type=ctype)
        disp = "inline" if (ctype == "application/pdf" or ctype.startswith("image/")) else "attachment"
        resp["Content-Disposition"] = f'{disp}; filename="file_{id_val}.{ctype.split("/")[-1]}"'
        return resp
    return handler

# Endpoints
serve_expense_bill_by_id        = _serve_blob("SELECT bill_photo FROM expense WHERE expense_id=%s LIMIT 1", param='expense_id')
serve_travel_fare_bill_by_id    = _serve_blob("SELECT bill_photo FROM travel_fare WHERE travel_fare_id=%s LIMIT 1", param='travel_fare_id')

from django.http import HttpResponse, HttpResponseNotFound

def serve_local_fare_bill_by_id(request, local_fare_id: int = None, **kwargs):
    guard = _require_login(request)
    if guard: return guard
    from contextlib import closing
    with closing(connection.cursor()) as cur:
        row = None
        try:
            id_val = local_fare_id if local_fare_id is not None else (list(kwargs.values())[0] if kwargs else None)
            cur.execute(
                "SELECT COALESCE(bill_photo, ref_image) FROM local_fare WHERE localfare_id=%s LIMIT 1",
                [id_val]
            )
            row = cur.fetchone()
        except Exception:
            try:
                cur.execute(
                    "SELECT COALESCE(bill_photo, ref_image) FROM local_fare WHERE local_id=%s LIMIT 1",
                    [id_val]
                )
                row = cur.fetchone()
            except Exception:
                row = None
    if not row or row[0] is None:
        return HttpResponseNotFound("No file found.")
    data = bytes(row[0])
    ctype = _guess_mime(data)
    resp = HttpResponse(data, content_type=ctype)
    disp = "inline" if (ctype == "application/pdf" or ctype.startswith("image/")) else "attachment"
    resp["Content-Disposition"] = f'{disp}; filename="file_{id_val}.{ctype.split("/")[-1]}"'
    return resp

serve_hotel_bill_by_id          = _serve_blob("SELECT bill_photo FROM hotel_accomodation WHERE hotel_acc_id=%s LIMIT 1", param='hotel_id')
serve_misc_bill_by_id           = _serve_blob("SELECT bill_photo FROM miscellaneous_expenses WHERE miscel_expense_id=%s LIMIT 1", param='misc_id')

import json
from django.views.decorators.csrf import csrf_exempt
from django.db import connection, transaction
from django.http import JsonResponse, HttpResponseBadRequest

def _ok(data=None, status=200):
    return JsonResponse({"ok": True, "data": data or {}}, status=status)

def _err(msg, status=400):
    return JsonResponse({"ok": False, "error": msg}, status=status)

def _get_json_or_form(request):
    # supports multipart (FormData) or JSON
    ctype = (request.META.get("CONTENT_TYPE") or "").lower()
    if ctype.startswith("application/json"):
        try:
            return json.loads(request.body.decode("utf-8") or "{}"), {}
        except Exception:
            return {}, {}
    # multipart: normal fields in POST, files in FILES
    return request.POST.dict(), request.FILES
def _mode_meta(name):
    if not name: return {"fixed_status": 0, "price": Decimal("0")}
    with connection.cursor() as cur:
        cur.execute("""
            SELECT COALESCE(fixed_status,0), COALESCE(price,0)
            FROM master_transport_mode
            WHERE LOWER(TRIM(mode_of_transport)) = LOWER(TRIM(%s))
            LIMIT 1
        """, [name])
        row = cur.fetchone()
    if not row: return {"fixed_status": 0, "price": Decimal("0")}
    return {"fixed_status": int(row[0] or 0), "price": Decimal(str(row[1] or "0"))}


@csrf_exempt
def api_create_travel_voucher_DEPRECATED(request):
    """
    Create TRAVEL voucher with optional section arrays.
    Accepts application/json or multipart (arrays as JSON strings).
    Only the sections that are present will be inserted.
    """
    if request.method != "POST":
        return _err("Only POST allowed", 405)

    body, files = _get_json_or_form(request)

    def parse_arr(v):
        if not v: return []
        if isinstance(v, list): return v
        if isinstance(v, str):
            s = v.strip()
            if s.startswith('['):
                try: return json.loads(s)
                except Exception: return []
        return []

    voucher      = parse_arr(body.get("voucher"))
    travel       = parse_arr(body.get("travel"))
    travel_fare  = parse_arr(body.get("travel_fare"))
    local_fare   = parse_arr(body.get("local_fare"))
    hotels       = parse_arr(body.get("hotel_accomodation"))
    da_entries   = parse_arr(body.get("food"))
    misc_entries = parse_arr(body.get("miscellaneous_expenses"))

    if not voucher or not travel:
        return _err("voucher[] and travel[] are required at minimum.", 400)

    v0 = voucher[0] or {}
    t0 = travel[0] or {}

    username     = (v0.get("username") or "").strip()
    emp_id       = _get_emp_id_from_request(request, username)
    if emp_id is None:
        return _err("Employee not found or not logged in.", 401)

    upload_date  = _normalize_date(v0.get("upload_date") or "")
    expense_date = _normalize_date(v0.get("expense_date") or "")
    work_order   = (v0.get("work_order_no") or "").strip()
    voucher_type = (v0.get("voucher_type") or "TRAVEL").strip().upper()

    if not (work_order and upload_date and (t0.get("from_date") and t0.get("to_date"))):
        return _err("Missing required travel details (work_order/upload_date/from/to).", 400)

    voucher_id = _generate_voucher_id(emp_id, upload_date, voucher_type)
    status = _manager_approve_seq_for(emp_id)


    with transaction.atomic():
        with connection.cursor() as cur:
            # Header
            cur.execute("""
                INSERT INTO voucher (voucher_id, work_order_no, upload_date, expense_date, voucher_type, total_amount, emp_id, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, [voucher_id, work_order, upload_date, expense_date or upload_date, voucher_type, float(v0.get("total_amount") or 0) or 0, emp_id, status]
            )

            cur.execute("""
                INSERT INTO travel (voucher_id, projectname, place, purpose_journey, place_visit, from_date, to_date, visit_authorised)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, [
                voucher_id,
                t0.get("projectname") or "",
                t0.get("place") or "",
                t0.get("purpose_journey") or "",
                t0.get("place_visit") or t0.get("place") or "",
                t0.get("from_date") or None,
                t0.get("to_date") or None,
                t0.get("visit_authorised") or t0.get("visit_authorised") or ""
            ])

            cur.execute("SELECT travel_id FROM travel WHERE voucher_id=%s ORDER BY travel_id DESC LIMIT 1", [voucher_id])
            r = cur.fetchone()
            if not r:
                raise Exception("Failed to obtain travel_id")
            travel_id = int(r[0])

            # Helper: lookup mode meta
            def _mode_meta(name):
                if not name: return {"fixed_status": 0, "price": D(0)}
                with connection.cursor() as c2:
                    c2.execute("""
                        SELECT COALESCE(fixed_status,0), COALESCE(price,0)
                        FROM master_transport_mode
                        WHERE LOWER(TRIM(mode_of_transport)) = LOWER(TRIM(%s))
                        LIMIT 1
                    """, [name])
                    rr = c2.fetchone()
                if not rr: return {"fixed_status": 0, "price": D(0)}
                return {"fixed_status": int(rr[0] or 0), "price": D(rr[1])}

            # travel_fare
            for it in travel_fare:
                if not isinstance(it, dict): continue
                mode = it.get("mode_transport") or it.get("mode_trasport") or ""
                meta = _mode_meta(mode)
                fixed = meta["fixed_status"]
                price = meta["price"]
                km = D(it.get("km") or it.get("number_km"), "0")
                if fixed == 1:
                    amount = (km * price).quantize(Decimal("0.01"))
                else:
                    amount = D(it.get("amount") or it.get("cost"), "0.00").quantize(Decimal("0.01"))

                cur.execute("""
                    INSERT INTO travel_fare
                    (travel_id, from_place, to_place, departure_date, departure_time, arrival_date, arrival_time, mode_transport, cost, bill_photo)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, [
                    travel_id,
                    it.get("from_place") or "",
                    it.get("to_place") or "",
                    it.get("departure_date") or None,
                    it.get("departure_time") or None,
                    it.get("arrival_date") or None,
                    it.get("arrival_time") or None,
                    mode,
                    str(amount),
                    b64bytes(it.get("bill_photo"))
                ])

            # local_fare
            for it in local_fare:
                if not isinstance(it, dict): continue
                mode = it.get("mode_transport") or it.get("mode_trasport") or ""
                meta = _mode_meta(mode)
                fixed = meta["fixed_status"]
                price = meta["price"]
                km_val = D(it.get("number_km") or it.get("km"), "0")
                if fixed == 1:
                    amount = (km_val * price).quantize(Decimal("0.01"))
                    km_out = str(km_val)
                else:
                    amount = D(it.get("amount"), "0.00").quantize(Decimal("0.01"))
                    km_out = None

                cur.execute("""
                    INSERT INTO local_fare
                    (travel_id, uploaded_date, fromplace, toplace, mode_transport, number_km, amount, ref_image)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """, [
                    travel_id,
                    it.get("date") or None,
                    it.get("fromplace") or "",
                    it.get("toplace") or "",
                    mode,
                    km_out,
                    str(amount),
                    b64bytes(it.get("ref_image"))
                ])

            # hotel_accomodation
            for it in hotels:
                if not isinstance(it, dict): continue
                amt = D(it.get("total_amount"), "0.00").quantize(Decimal("0.01"))
                cur.execute("""
                    INSERT INTO hotel_accomodation
                    (travel_id, checkin_date, checkin_time, checkout_date, checkout_time, hotel_name, adress, total_amount, bill_photo)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, [
                    travel_id,
                    it.get("checkin_date") or None,
                    it.get("checkin_time") or None,
                    it.get("checkout_date") or None,
                    it.get("checkout_time") or None,
                    it.get("hotel_name") or "",
                    it.get("adress") or "",
                    str(amt),
                    b64bytes(it.get("bill_photo"))
                ])

            # food (DA)
            for it in da_entries:
                if not isinstance(it, dict): continue
                fd = it.get("fromdate") or it.get("from_date")
                td = it.get("todate") or it.get("to_date")
                days = it.get("number_days")
                if not days and fd and td:
                    try:
                        from datetime import datetime as _dt
                        d1 = _dt.strptime(fd, "%Y-%m-%d").date()
                        d2 = _dt.strptime(td, "%Y-%m-%d").date()
                        days = (d2 - d1).days + 1 if d2 >= d1 else 0
                    except Exception:
                        days = 0
                amt = D(it.get("amount"), "0.00").quantize(Decimal("0.01"))
                cur.execute("""
                    INSERT INTO food (travel_id, fromdate, todate, number_days, amount)
                    VALUES (%s,%s,%s,%s,%s)
                """, [travel_id, fd or None, td or None, int(days or 0), str(amt)])

            # misc
            for it in misc_entries:
                if not isinstance(it, dict): continue
                amt = D(it.get("amount"), "0.00").quantize(Decimal("0.01"))
                cur.execute("""
                    INSERT INTO miscellaneous_expenses
                    (travel_id, uploaded_date, particulars, amount, bill_photo)
                    VALUES (%s,%s,%s,%s,%s)
                """, [
                    travel_id,
                    it.get("date") or None,
                    it.get("particulars") or it.get("perticulers") or "",
                    str(amt),
                    b64bytes(it.get("bill_photo"))
                ])

            # recompute and update voucher.total_amount from DB
            total = recompute_voucher_total(cur, voucher_id, travel_id)
            # conn.commit()
            def _sum(sql):
                cur.execute(sql, [travel_id])
                rr = cur.fetchone()
                return D(rr[0], "0.00") if rr and rr[0] is not None else D("0.00")

            sum_fare  = _sum("SELECT COALESCE(SUM(cost),0) FROM travel_fare WHERE travel_id=%s")
            sum_local = _sum("SELECT COALESCE(SUM(amount),0) FROM local_fare WHERE travel_id=%s")
            sum_hotel = _sum("SELECT COALESCE(SUM(total_amount),0) FROM hotel_accomodation WHERE travel_id=%s")
            sum_food  = _sum("SELECT COALESCE(SUM(amount),0) FROM food WHERE travel_id=%s")
            sum_misc  = _sum("SELECT COALESCE(SUM(amount),0) FROM miscellaneous_expenses WHERE travel_id=%s")
            # grand_total = (sum_fare + sum_local + sum_hotel + sum_food + sum_misc).quantize(Decimal("0.01"))

            cur.execute("UPDATE voucher SET total_amount=%s WHERE voucher_id=%s", [str(total), voucher_id])

    return _ok({"voucher_id": voucher_id, "travel_id": travel_id, "total_amount": float(total)}, status=201)
from decimal import Decimal

def recompute_voucher_total(cur, voucher_id, travel_id):
    """
    Recomputes total from child tables and updates voucher.total_amount.
    Child tables & columns assumed:
      travel_fare(cost), local_fare(amount), hotel_accomodation(amount),
      food(amount), miscellaneous_expenses(amount)
    """
    def _sum(table, col):
        cur.execute(f"SELECT COALESCE(SUM({col}),0) FROM {table} WHERE travel_id=%s", [travel_id])
        return Decimal(str(cur.fetchone()[0] or 0))

    total = Decimal("0.00")
    total += _sum("travel_fare", "cost")
    total += _sum("local_fare", "amount")
    total += _sum("hotel_accomodation", "amount")
    total += _sum("food", "amount")
    total += _sum("miscellaneous_expenses", "amount")

    # persist on voucher (store as string to avoid float issues in drivers)
    cur.execute("UPDATE voucher SET total_amount=%s WHERE voucher_id=%s", [str(total), voucher_id])
    return total

@require_GET
def master_travel_list(request):
    with connection.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT purpose_journey, visit_authorise_name
            FROM master_travel
            ORDER BY purpose_journey NULLS LAST, visit_authorise_name NULLS LAST
        """)
        rows = cur.fetchall()
    data = [{"purpose_journey": r[0], "visit_authorise_name": r[1]} for r in rows]
    return JsonResponse(data, safe=False)

@csrf_exempt
def api_create_expense_voucher(request):
    """
    Accepts JSON or multipart form.

    JSON:
      { "items":[{"date":"YYYY-MM-DD","particulars":"Conveyance","amount":123.45}, ...] }

    multipart/form-data:
      items=<the JSON above>
      + optional per-row files: expense_files_0, expense_files_1, ...
      + or a single 'bill' to apply to all rows

    Writes:
      expense(voucher_id, expense_type, total_amount, bill_photo)
      voucher(total_amount = sum of row amounts)
    """
    if request.method != "POST":
        return _err("Only POST allowed", 405)

    body, files = _get_json_or_form(request)

    # items list
    raw_items = body.get("items") or body.get("cash_items") or []
    if isinstance(raw_items, str):
        try:
            items = json.loads(raw_items) if raw_items.strip() else []
        except Exception:
            items = []
    else:
        items = raw_items

    if not items or not isinstance(items, list):
        return _err("No expense items provided.")

    # files: per-row or single default
    bills_by_index = {}
    if files:
        for k, f in files.items():
            if k.startswith("expense_files_"):
                try:
                    idx = int(k.split("_")[-1])
                    bills_by_index[idx] = f
                except Exception:
                    pass
    default_bill = files.get("bill") if files else None
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    try:
        b = _parse_voucher_json(request)
    except ValueError as e:
        return _err(str(e), 400)

    # Enforce: if items provided, a bill is required (either default or per-row)
    if not default_bill and not any(k.startswith("expense_files_") for k in (files or {})):
        return _err("Bill file is required for expense vouchers.", 400)

    # compute grand total
    try:
        grand_total = round(sum(float(i.get("amount") or 0) for i in items), 2)
    except Exception:
        return _err("Amounts must be numeric.")
    v_type = "expense"
    upload_date  = (body.get("upload_date") or body.get("date") or "").strip()
    expense_date = (body.get("expense_date") or body.get("bill_date") or "").strip()
    # work_order  = (b.get('workordernumber') or b.get('work_order_no') or '').strip()
    work_order_no = (b.get("work_order_no") or b.get("work_order_number") or "").strip()
    
    auth   = request.session.get("auth") or {}
    emp_id = int(auth.get("emp_id")) if str(auth.get("emp_id") or "").isdigit() else None
    if emp_id is None:
        return _err("Not authenticated: emp_id missing in session.", 401)

    status = _manager_approve_seq_for(emp_id)
    
    if emp_id is None:
        return _err("Not authenticated: emp_id missing in session.", 401)

    voucher_id = _generate_voucher_id(emp_id, upload_date or None, v_type)

    try:
        emp_id = int(auth.get("emp_id")) if auth.get("emp_id") is not None else None
    except Exception:
        emp_id = None

    try:
        with transaction.atomic():
            # create header (generate EV id if none supplied)
            if not voucher_id:
                voucher_id = _generate_voucher_id(emp_id, upload_date or None,v_type) if emp_id else None

            with connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO voucher (voucher_id,work_order_no, upload_date, expense_date, voucher_type, total_amount, Emp_id,status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, [
                    voucher_id, work_order_no, (upload_date or None), (expense_date or None),
                    'expense', grand_total, emp_id,status
                ])

            # each expense line
            with connection.cursor() as cur:
                for idx, it in enumerate(items):
                    particulars = (it.get("particulars") or it.get("expense_type") or "").strip()
                    remarks = (it.get("remarks") or  "").strip()
                    amount = float(it.get("amount") or 0)
                    bill = bills_by_index.get(idx) or default_bill
                    bill_bytes = bill.read() if bill else None
                    cur.execute(
                        "INSERT INTO expense (voucher_id, expense_type, total_amount,remarks, bill_photo) VALUES (%s, %s, %s, %s, %s)",
                        [voucher_id, particulars, amount, remarks, bill_bytes]
                    )
                    _insert_voucher_status_row(voucher_id, emp_id)

        return _ok({
            "voucher_id": voucher_id,
            "total_amount": grand_total,
        }, status=201)
    except Exception as e:
        return _err(f"DB error: {e}", 500)
    
def api_master_travel_lists(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])
    with connection.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT purpose_journey
            FROM master_travel
            WHERE purpose_journey IS NOT NULL AND TRIM(purpose_journey) <> ''
            ORDER BY purpose_journey
        """)
        purposes = [r[0] for r in cur.fetchall()]

        cur.execute("""
            SELECT DISTINCT visit_authoriser_name
            FROM master_travel
            WHERE visit_authoriser_name IS NOT NULL AND TRIM(visit_authoriser_name) <> ''
            ORDER BY visit_authoriser_name
        """)
        authorisers = [r[0] for r in cur.fetchall()]

    return JsonResponse({
        "purpose_journey": purposes,
        "visit_authoriser_name": authorisers,
    })

def api_auth_me(request):
    """Return basic user info and approve_seq for UI gating.

    Response JSON:
      { name: str, designation: str, approve_seq: int }
    """
    auth = request.session.get("auth") or {}
    name = request.session.get("display_name") or auth.get("username") or ""
    designation = request.session.get("role") or auth.get("role") or request.session.get("designation") or ""

    approve_seq = 0
    emp_id = 0
    try:
        emp_id = int(auth.get("emp_id") or 0)
    except Exception:
        emp_id = 0
    if emp_id:
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT COALESCE(approve_seq,0) FROM Credentials WHERE emp_id=%s LIMIT 1", [emp_id])
                row = cur.fetchone()
                if row and row[0] is not None:
                    approve_seq = int(row[0])
        except Exception:
            # On any DB error, keep default 0 to be safe
            approve_seq = 0

    return JsonResponse({"name": name, "designation": designation, "approve_seq": approve_seq})

@require_GET
def api_managers_list(request):
    """Return a list of names for managers higher than the logged-in employee.

    Uses employee.reporting_manager chain (up to 4 levels) to determine higher posts.
    Response: [ {"emp_id": int, "name": str} ] in top-down order.
    If not logged in or no chain, returns an empty list.
    """
    auth = request.session.get("auth") or {}
    try:
        emp_id = int(auth.get("emp_id") or 0)
    except Exception:
        emp_id = 0
    if not emp_id:
        return JsonResponse([], safe=False)

    ids = _manager_chain(emp_id, 4)
    if not ids:
        return JsonResponse([], safe=False)

    # Preserve order of ids from the chain
    ph = ",".join(["%s"] * len(ids))
    name_by_id = {}
    with connection.cursor() as cur:
        cur.execute(f"SELECT emp_id, COALESCE(name,'') FROM employee WHERE emp_id IN ({ph})", ids)
        for i, n in cur.fetchall():
            name_by_id[int(i)] = n or ""

    data = [{"emp_id": i, "name": name_by_id.get(i, "")} for i in ids]
    return JsonResponse(data, safe=False)

# ---------------- Projects (Admin only) ----------------
from django.views.decorators.http import require_http_methods

@csrf_exempt
@require_http_methods(["POST"])
def api_projects_upsert(request):
    """Create or update a project row.

    AuthZ: Admin only (role contains 'admin').

    Request JSON:
      { project_id?: int,
        work_order_no: str,
        project_name: str,
        client_name?: str,
        project_type?: str,
        place?: str,
        address?: str,
        dept_id?: int,
        status?: str }

    Response: { ok: true, data: { project_id: int, updated: bool } }
    """
    auth = request.session.get("auth") or {}
    if not auth:
        return _err("Not authenticated", 401)
    if not _require_admin(request):
        return _err("Forbidden: Admin only", 403)

    data = _json(request)
    # Read fields safely
    def s(k):
        v = data.get(k)
        return ("" if v is None else str(v)).strip()
    def n(k):
        try:
            return int(data.get(k)) if data.get(k) not in (None, "", []) else None
        except Exception:
            return None

    project_id = n("project_id")
    work_order_no = s("work_order_no")
    project_name = s("project_name")
    client_name  = s("client_name")
    project_type = s("project_type")
    place        = s("place")
    address      = s("address")
    dept_id      = n("dept_id")
    status       = s("status")

    if not work_order_no or not project_name:
        return _err("work_order_no and project_name are required", 400)

    try:
        with connection.cursor() as cur:
            if project_id and project_id > 0:
                # UPDATE existing
                cur.execute(
                    """
                    UPDATE projects
                    SET work_order_no=%s, project_name=%s, client_name=%s, project_type=%s,
                        place=%s, address=%s, dept_id=%s, status=%s
                    WHERE project_id=%s
                    """,
                    [work_order_no, project_name, client_name or None, project_type or None,
                     place or None, address or None, dept_id, status or None, project_id]
                )
                return _ok({"project_id": int(project_id), "updated": True})
            else:
                # If a project with the same work_order_no exists, update it; otherwise insert new.
                cur.execute("SELECT project_id FROM projects WHERE work_order_no=%s LIMIT 1", [work_order_no])
                row = cur.fetchone()
                if row:
                    pid = int(row[0])
                    cur.execute(
                        """
                        UPDATE projects
                        SET work_order_no=%s, project_name=%s, client_name=%s, project_type=%s,
                            place=%s, address=%s, dept_id=%s, status=%s
                        WHERE project_id=%s
                        """,
                        [work_order_no, project_name, client_name or None, project_type or None,
                         place or None, address or None, dept_id, status or None, pid]
                    )
                    return _ok({"project_id": pid, "updated": True})
                else:
                    new_id = _next_id("projects", "project_id")
                    cur.execute(
                        """
                        INSERT INTO projects
                        (project_id, work_order_no, project_name, client_name, project_type, place, address, dept_id, status)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        [new_id, work_order_no, project_name, client_name or None, project_type or None,
                         place or None, address or None, dept_id, status or None]
                    )
                    return _ok({"project_id": int(new_id), "updated": False}, 201)
    except Exception as e:
        return _err(f"DB error: {e}", 500)

@require_GET
def api_project_details(request, work_order_no: str):
    """Return full project row by work order number.

    Response: 200 with JSON object or 404 if not found.
    """
    wo = (work_order_no or "").strip()
    if not wo:
        return _err("work_order_no required", 400)
    try:
        with connection.cursor() as cur:
            cur.execute(
                """
                SELECT project_id, work_order_no, project_name, client_name, project_type,
                       place, address, dept_id, status
                FROM projects
                WHERE work_order_no=%s
                LIMIT 1
                """,
                [wo]
            )
            row = cur.fetchone()
            if not row:
                return HttpResponseNotFound("project not found")
            data = {
                "project_id": int(row[0]),
                "work_order_no": row[1],
                "project_name": row[2],
                "client_name": row[3],
                "project_type": row[4],
                "place": row[5],
                "address": row[6],
                "dept_id": (int(row[7]) if (row[7] is not None and str(row[7]).isdigit()) else None),
                "status": row[8],
            }
            return JsonResponse(data)
    except Exception as e:
        return _err(f"DB error: {e}", 500)
# # Optional: master/travel list (to feed Purpose / Authorised selects)
# def master_travel_list(request):
#     try:
#         with connection.cursor() as cur:
#             cur.execute("SELECT purpose_journey, visit_authoriser_name, food_per_day, status FROM master_travel")
#             rows = cur.fetchall()
#         data = [
#             {
#                 "purpose_journey": r[0],
#                 "visit_authoriser_name": r[1],
#                 "food_per_day": r[2],
#                 "status": r[3],
#             }
#             for r in rows
#         ]
#         return JsonResponse(data, safe=False)
#     except Exception as e:
#         return _err(f"Master load failed: {e}", 500)




@require_GET
def api_master_food_rate(request):
    """Return food_per_day rate for a given purpose_journey (max if not found)."""
    purpose = (request.GET.get("purpose") or "").strip()
    try:
        with connection.cursor() as cur:
            if purpose:
                cur.execute("""SELECT COALESCE(MAX(food_per_day), 0)
                                 FROM master_travel
                                 WHERE purpose_journey=%s""", [purpose])
            else:
                cur.execute("""SELECT COALESCE(MAX(food_per_day), 0)
                                 FROM master_travel""")
            row = cur.fetchone()
            rate = float(row[0] or 0)
        return JsonResponse({ "ok": True, "data": { "food_per_day": rate } })
    except Exception as e:
        return JsonResponse({ "ok": False, "error": f"rate lookup failed: {e}" }, status=500)

@require_GET
def api_master_transport_modes(request):
    """
    Returns transport modes with fixed_status and price/UOM, e.g.:
    [{"mode_of_transport":"Bike","fixed_status":1,"price":"4.50","UOM":"km"}, ...]
    """
    with connection.cursor() as cur:
        cur.execute("""
            SELECT mode_of_transport, COALESCE(fixed_status,0), price, COALESCE(UOM,'')
            FROM master_transport_mode
            ORDER BY mode_of_transport
        """)
        rows = cur.fetchall()

    data = [
        {
            "mode_of_transport": r[0],
            "fixed_status": int(r[1] or 0),
            "price": str(r[2] if r[2] is not None else 0),
            "UOM": r[3],
        }
        for r in rows
    ]
    return JsonResponse(data, safe=False)


def _travel_purpose_rate(purpose_name: str) -> float:
    """
    Returns food_per_day (DA) for a given travel purpose from master_travel (or similar) table.
    Falls back to 250 if not found.
    """
    if not purpose_name:
        return 250.0
    try:
        with connection.cursor() as cur:
            # Try common schemas: (purpose, food_per_day) or (purpose_name, da)
            cur.execute("""
                SELECT COALESCE(MAX(food_per_day), MAX(da), MAX(rate), 0)
                FROM master_travel
                WHERE LOWER(purpose)=LOWER(%s) OR LOWER(purpose_name)=LOWER(%s) OR LOWER(purpose_journey)=LOWER(%s)
            """, [purpose_name, purpose_name, purpose_name])
            row = cur.fetchone()
            if row and row[0]:
                return float(row[0])
    except Exception:
        pass
    return 250.0


@csrf_exempt
def api_save_travel_voucher(request):
    """
    Save TRAVEL voucher using strict JSON like the user's example.
    Body shape:
    {
      "voucher": [ {...} ],
      "travel": [ {...} ],
      "travel_fare": [ {...} ],
      "local_fare": [ {...} ],
      "hotel_accomodation": [ {...} ],
      "food": [ {...} ],
      "miscellaneous_expenses": [ {...} ]
    }
    Only present, non-empty sections are inserted.
    File-like fields must be base64 strings (raw or data URLs).
    """
    if request.method != "POST":
        return _err("Only POST allowed", 405)

    ctype = (request.META.get("CONTENT_TYPE") or "").lower()

    voucher = travel = travel_fare = local_fare = hotels = da_entries = misc_entries = None
    v0 = {}
    t0 = {}

    if ctype.startswith("application/json"):
        try:
            body = json.loads((request.body or b"").decode("utf-8") or "{}")
        except Exception:
            return _err("Invalid JSON", 400)

        def arr(key):
            v = body.get(key)
            if isinstance(v, list):
                return v
            return []

        voucher      = arr("voucher")
        travel       = arr("travel")
        travel_fare  = arr("travel_fare")
        local_fare   = arr("local_fare")
        hotels       = arr("hotel_accomodation")
        da_entries   = arr("food")
        misc_entries = arr("miscellaneous_expenses")

        if not voucher or not travel:
            return _err("voucher[] and travel[] are required at minimum.", 400)

        v0 = dict(voucher[0] or {})
        t0 = dict(travel[0] or {})
    else:
        # Support multipart/form-data from the legacy UI
        body, files = _get_json_or_form(request)

        def arr_json(key):
            raw = body.get(key)
            if isinstance(raw, list):
                return raw
            if isinstance(raw, str):
                try:
                    return json.loads(raw) if raw.strip() else []
                except Exception:
                    return []
            return []

        # Build v0/t0 from simple fields; infer where necessary
        work_order_no = (body.get('work_order_no') or body.get('workordernumber') or body.get('projectname') or '').strip()
        upload_date   = (body.get('upload_date') or body.get('uploadate') or body.get('date') or '')
        if not upload_date:
            try:
                from datetime import date as _d
                upload_date = _d.today().isoformat()
            except Exception:
                upload_date = ''
        expense_date  = (body.get('expense_date') or body.get('bill_date') or body.get('from_date') or upload_date or '')

        v0 = {
            'work_order_no': work_order_no,
            'upload_date':   _normalize_date(upload_date) if upload_date else upload_date,
            'expense_date':  _normalize_date(expense_date) if expense_date else expense_date,
            'voucher_type':  'TRAVEL',
            'total_amount':  body.get('total_amount') or 0,
            'username':      body.get('username') or '',
        }

        t0 = {
            'projectname':      body.get('projectname') or '',
            'place':            body.get('place') or '',
            'purpose_journey':  body.get('purpose_journey') or body.get('purpose') or '',
            'place_visit':      body.get('place_visit') or body.get('place') or '',
            'from_date':        body.get('from_date') or '',
            'to_date':          body.get('to_date') or '',
            'visit_authorised': body.get('visit_authorised') or body.get('visit_autherized') or '',
        }

        # Lists + attach uploaded files by index (first file per index). Be tolerant to
        # variations: if index is missing, map files sequentially by occurrence.
        def _first_file(key):
            try:
                if hasattr(files, 'getlist'):
                    lst = files.getlist(key)
                    return lst[0] if lst else None
            except Exception:
                pass
            try:
                return files.get(key)
            except Exception:
                return None

        # Collect all posted fare/local/hotel/misc file keys for sequential fallback.
        # Be liberal in matching: accept keys containing these tokens, prioritizing specific ones first.
        fare_file_objs = []
        local_file_objs = []
        hotel_file_objs = []
        misc_file_objs = []
        try:
            key_iter = (files.keys() if hasattr(files, 'keys') else list(files) if files else [])
            for k in key_iter:
                ks = str(k or '')
                lks = ks.lower()
                def _add(target_list, key):
                    f = _first_file(key)
                    if f: target_list.append(f)
                # Strict prefixes
                if lks.startswith('fare_files_'):
                    _add(fare_file_objs, k); continue
                if lks.startswith('local_files_'):
                    _add(local_file_objs, k); continue
                if lks.startswith('hotel_files_'):
                    _add(hotel_file_objs, k); continue
                if lks.startswith('misc_files_'):
                    _add(misc_file_objs, k); continue
                # Liberal matching: classify by containing tokens; order matters to avoid 'local fare' misclassify
                if ('local' in lks) and ('file' in lks or 'bill' in lks):
                    _add(local_file_objs, k); continue
                if ('hotel' in lks) and ('file' in lks or 'bill' in lks):
                    _add(hotel_file_objs, k); continue
                if ('misc' in lks) and ('file' in lks or 'bill' in lks):
                    _add(misc_file_objs, k); continue
                if ('fare' in lks) and ('file' in lks or 'bill' in lks):
                    _add(fare_file_objs, k); continue
        except Exception:
            pass

        base_fare = arr_json('travel_fare')
        travel_fare = []
        seq_i = 0
        for it in base_fare:
            if not isinstance(it, dict):
                continue
            dep = (it.get('dep') or '').strip()
            arrv = (it.get('arr') or '').strip()
            d_d, d_t = (dep.split('T', 1)+[''])[:2] if dep else (None, None)
            a_d, a_t = (arrv.split('T', 1)+[''])[:2] if arrv else (None, None)
            idx = it.get('index')
            blob = None
            if files is not None:
                if idx is not None:
                    k = f'fare_files_{idx}'
                    fobj = _first_file(k)
                    blob = fobj.read() if fobj else None
                # fallback: assign next sequential file
                if not blob and seq_i < len(fare_file_objs):
                    fobj = fare_file_objs[seq_i]; seq_i += 1
                    blob = fobj.read() if hasattr(fobj, 'read') else None
            # if no uploaded file part, accept inline base64 from JSON item
            if not blob:
                inline = it.get('bill_photo') or it.get('bill') or ''
                try:
                    if isinstance(inline, (bytes, bytearray)):
                        blob = bytes(inline)
                    elif isinstance(inline, str) and inline.strip():
                        blob = b64bytes(inline)
                except Exception:
                    blob = None
            travel_fare.append({
                'from_place': it.get('from_place') or it.get('from') or '',
                'to_place':   it.get('to_place') or it.get('to') or '',
                'departure_date': d_d or None,
                'departure_time': d_t or None,
                'arrival_date':   a_d or None,
                'arrival_time':   a_t or None,
                'mode_transport': it.get('mode_transport') or it.get('mode_trasport') or it.get('mode') or '',
                'cost': it.get('cost') if str(it.get('cost') or '').strip() else it.get('amount') or 0,
                'bill_photo': blob,
            })

        base_local = arr_json('local_fare')
        local_fare = []
        seq_i = 0
        for it in base_local:
            if not isinstance(it, dict):
                continue
            idx = it.get('index')
            blob = None
            if files is not None and idx is not None:
                fobj = _first_file(f'local_files_{idx}')
                if fobj: blob = fobj.read()
            if not blob and seq_i < len(local_file_objs):
                fobj = local_file_objs[seq_i]; seq_i += 1
                blob = fobj.read() if hasattr(fobj, 'read') else None
            # inline base64 fallback from JSON item
            if not blob:
                inline = it.get('ref_image') or it.get('bill_photo') or ''
                try:
                    if isinstance(inline, (bytes, bytearray)):
                        blob = bytes(inline)
                    elif isinstance(inline, str) and inline.strip():
                        blob = b64bytes(inline)
                except Exception:
                    blob = None
            local_fare.append({
                'date': it.get('date') or None,
                'fromplace': it.get('fromplace') or it.get('from') or '',
                'toplace': it.get('toplace') or it.get('to') or '',
                'mode_transport': it.get('mode_transport') or it.get('mode_trasport') or it.get('mode') or '',
                'number_km': it.get('number_km') or it.get('km'),
                'amount': it.get('amount') or 0,
                'ref_image': blob,
            })

        base_hotels = arr_json('hotel_accomodation')
        hotels = []
        seq_i = 0
        for it in base_hotels:
            if not isinstance(it, dict):
                continue
            cin = (it.get('checkin') or '').strip(); cout = (it.get('checkout') or '').strip()
            ci_d, ci_t = (cin.split('T',1)+[''])[:2] if cin else (None,None)
            co_d, co_t = (cout.split('T',1)+[''])[:2] if cout else (None,None)
            idx = it.get('index')
            blob = None
            if files is not None and idx is not None:
                fobj = _first_file(f'hotel_files_{idx}')
                if fobj: blob = fobj.read()
            if not blob and seq_i < len(hotel_file_objs):
                fobj = hotel_file_objs[seq_i]; seq_i += 1
                blob = fobj.read() if hasattr(fobj, 'read') else None
            if not blob:
                inline = it.get('bill_photo') or it.get('bill') or ''
                try:
                    if isinstance(inline, (bytes, bytearray)):
                        blob = bytes(inline)
                    elif isinstance(inline, str) and inline.strip():
                        blob = b64bytes(inline)
                except Exception:
                    blob = None
            hotels.append({
                'checkin_date': ci_d or it.get('checkin_date') or None,
                'checkin_time': ci_t or it.get('checkin_time') or None,
                'checkout_date': co_d or it.get('checkout_date') or None,
                'checkout_time': co_t or it.get('checkout_time') or None,
                'hotel_name': it.get('hotel_name') or it.get('name') or '',
                'adress': it.get('adress') or it.get('address') or '',
                'total_amount': it.get('total_amount') or it.get('amount') or 0,
                'bill_photo': blob,
            })

        base_da = arr_json('food')
        da_entries = []
        for it in base_da:
            if not isinstance(it, dict): continue
            da_entries.append({
                'fromdate': it.get('fromdate') or it.get('from') or '',
                'todate': it.get('todate') or it.get('to') or '',
                'number_days': it.get('number_days') or 0,
                'amount': it.get('amount') or None,
            })

        base_misc = arr_json('miscellaneous_expenses')
        misc_entries = []
        seq_i = 0
        for it in base_misc:
            if not isinstance(it, dict): continue
            idx = it.get('index')
            blob = None
            if files is not None and idx is not None:
                fobj = _first_file(f'misc_files_{idx}')
                if fobj: blob = fobj.read()
            if not blob and seq_i < len(misc_file_objs):
                fobj = misc_file_objs[seq_i]; seq_i += 1
                blob = fobj.read() if hasattr(fobj, 'read') else None
            if not blob:
                inline = it.get('bill_photo') or it.get('bill') or ''
                try:
                    if isinstance(inline, (bytes, bytearray)):
                        blob = bytes(inline)
                    elif isinstance(inline, str) and inline.strip():
                        blob = b64bytes(inline)
                except Exception:
                    blob = None
            misc_entries.append({
                'date': it.get('date') or None,
                'perticulers': it.get('perticulers') or it.get('particulars') or '',
                'amount': it.get('amount') or 0,
                'bill_photo': blob,
            })

    username     = (v0.get("username") or "").strip()
    emp_id       = _get_emp_id_from_request(request, username)
    if emp_id is None:
        return _err("Employee not found or not logged in.", 401)

    upload_date  = _normalize_date(v0.get("upload_date") or "")
    expense_date = _normalize_date(v0.get("expense_date") or "") or upload_date
    work_order   = (v0.get("work_order_no") or "").strip()
    voucher_type = (v0.get("voucher_type") or "TRAVEL").strip().upper()

    if not (work_order and upload_date and (t0.get("from_date") and t0.get("to_date"))):
        return _err("Missing required travel details (work_order/upload_date/from/to).", 400)

    voucher_id = _generate_voucher_id(emp_id, upload_date, voucher_type)
    status = _manager_approve_seq_for(emp_id)

    grand_total = 0.0
    travel_id = None

    try:
        with transaction.atomic():

            # Header
            with connection.cursor() as cur:
                cur.execute("""
                    INSERT INTO voucher (voucher_id, work_order_no, upload_date, expense_date, voucher_type, total_amount, emp_id,status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """, [voucher_id, work_order, upload_date, expense_date, voucher_type, float(v0.get("total_amount") or 0) or 0, emp_id,status])

                cur.execute("""
                    INSERT INTO travel (voucher_id, projectname, place, purpose_journey, place_visit, from_date, to_date, visit_authorised)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """, [
                    voucher_id,
                    t0.get("projectname") or "",
                    t0.get("place") or "",
                    t0.get("purpose_journey") or "",
                    t0.get("place_visit") or (t0.get("place") or ""),
                    t0.get("from_date") or None,
                    t0.get("to_date") or None,
                    t0.get("visit_autherized") or t0.get("visit_authorised") or ""  # accept either spelling
                ])
                _insert_voucher_status_row(voucher_id, emp_id)
                cur.execute("SELECT travel_id FROM travel WHERE voucher_id=%s ORDER BY travel_id DESC LIMIT 1", [voucher_id])
                row = cur.fetchone()
                if not row:
                    raise Exception("Failed to obtain travel_id")
                travel_id = int(row[0])

            # (A) Travel Fare
            if isinstance(travel_fare, list) and travel_fare:
                with connection.cursor() as cur:
                    for it in travel_fare:
                        if not isinstance(it, dict): continue
                        # Accept multiple shapes: separate date/time or combined ISO 'dep'/'arr'
                        dep_d  = it.get("departure_date") or it.get("dep_date") or ""
                        dep_t  = it.get("departure_time") or it.get("dep_time") or ""
                        arr_d  = it.get("arrival_date") or it.get("arr_date") or ""
                        arr_t  = it.get("arrival_time") or it.get("arr_time") or ""
                        if (not dep_d or not arr_d) and (it.get('dep') or it.get('arr')):
                            try:
                                dep_iso = (it.get('dep') or '').strip()
                                arr_iso = (it.get('arr') or '').strip()
                                if dep_iso:
                                    dd, dt = (dep_iso.split('T',1)+[''])[:2]; dep_d = dep_d or dd; dep_t = dep_t or dt
                                if arr_iso:
                                    ad, at = (arr_iso.split('T',1)+[''])[:2]; arr_d = arr_d or ad; arr_t = arr_t or at
                            except Exception:
                                pass
                        # Normalize and fallback to header dates if still empty (DB column NOT NULL)
                        dep_d = _normalize_date(dep_d) if dep_d else ''
                        arr_d = _normalize_date(arr_d) if arr_d else ''
                        if not dep_d:
                            dep_d = _normalize_date(t0.get('from_date') or v0.get('upload_date') or _date.today().isoformat())
                        if not arr_d:
                            arr_d = _normalize_date(t0.get('to_date') or dep_d or v0.get('upload_date') or _date.today().isoformat())
                        # Ensure non-null times: default to 00:00:00 if missing; also accept HH:MM
                        dep_t = (dep_t or '').strip()
                        arr_t = (arr_t or '').strip()
                        if 'T' in dep_t:
                            dep_t = dep_t.split('T',1)[-1]
                        if 'T' in arr_t:
                            arr_t = arr_t.split('T',1)[-1]
                        if dep_t and len(dep_t) == 5:
                            dep_t += ':00'
                        if arr_t and len(arr_t) == 5:
                            arr_t += ':00'
                        if not dep_t:
                            dep_t = '00:00:00'
                        if not arr_t:
                            arr_t = '00:00:00'
                        mode   = it.get("mode_transport") or it.get("mode_trasport") or it.get("mode") or ""
                        cost   = float(it.get("cost") or 0) if str(it.get("cost") or "").strip() else 0.0
                        bill_b = it.get("bill_photo")
                        if isinstance(bill_b, str):
                            bill_b = b64bytes(bill_b)
                        # Make bill optional: allow saving without bill even if row has content
                        # has_content = any([(it.get('from_place') or it.get('from') or ''), (it.get('to_place') or it.get('to') or ''), mode, str(cost).strip()])
                        # if has_content and not bill_b:
                        #     raise ValueError('Travel Fare row is missing bill file.')
                        cur.execute("""
                            INSERT INTO travel_fare (travel_id, from_place, to_place, departure_date, departure_time, arrival_date, arrival_time, mode_transport, cost, bill_photo)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, [
                            travel_id,
                            it.get("from_place") or "",
                            it.get("to_place") or "",
                            dep_d or None,
                            dep_t or None,
                            arr_d or None,
                            arr_t or None,
                            mode,
                            cost,
                            bill_b
                        ])
                        grand_total += cost

            # (B) Local Fare
            if isinstance(local_fare, list) and local_fare:
                with connection.cursor() as cur:
                    for it in local_fare:
                        if not isinstance(it, dict): continue
                        mode = it.get("mode_transport") or it.get("mode_trasport") or it.get("mode") or ""
                        km = it.get("number_km")
                        kmv = float(km) if str(km or "").strip() not in ("", "null", "None") else None
                        amount = it.get("amount")
                        # Auto-compute if fixed_status == 1 and km present and amount empty
                        if (amount in (None, "", "null", "None")) and kmv is not None:
                            meta = _mode_meta(mode)
                            if int(meta.get("fixed_status") or 0) == 1:
                                try:
                                    amount = float(kmv) * float(meta.get("price") or 0)
                                except Exception:
                                    amount = 0.0
                        amt = float(amount or 0) if str(amount or "").strip() else 0.0
                        ref_b = b64bytes(it.get("ref_image"))
                        # Make bill optional for local travel entries as well
                        # if ( (it.get('fromplace') or it.get('from') or '') or (it.get('toplace') or it.get('to') or '') or mode or amt>0 ) and not ref_b:
                        #     raise ValueError('Local Travel row is missing bill file.')
                        # Accept both ISO datetime or just date
                        dt = it.get("date") or ""
                        cur.execute("""
                            INSERT INTO local_fare (travel_id, uploaded_date, fromplace, toplace, mode_transport, number_km, amount, ref_image)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        """, [
                            travel_id,
                            dt or None,
                            it.get("fromplace") or "",
                            it.get("toplace") or "",
                            mode,
                            kmv if kmv is not None else None,
                            amt,
                            ref_b
                        ])
                        grand_total += amt

            # (C) Hotel
            if isinstance(hotels, list) and hotels:
                with connection.cursor() as cur:
                    for it in hotels:
                        if not isinstance(it, dict): continue
                        bill_b = it.get("bill_photo")
                        if isinstance(bill_b, str):
                            bill_b = b64bytes(bill_b)
                        # Make bill optional for hotel entries, even when amount provided
                        # if (str(it.get('total_amount') or it.get('amount') or '').strip() not in ("", "0", "0.0", "0.00")) and not bill_b:
                        #     raise ValueError('Hotel row is missing bill file.')
                        cur.execute("""
                            INSERT INTO hotel_accomodation (travel_id, checkin_date, checkin_time, checkout_date, checkout_time, hotel_name, adress, total_amount, bill_photo)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, [
                            travel_id,
                            it.get("checkin_date") or None,
                            # Time columns are NOT NULL in DB; default to 00:00:00 if absent
                            (lambda s: (s+':00') if (s and len(s)==5) else (s or '00:00:00'))(it.get("checkin_time") or ""),
                            it.get("checkout_date") or None,
                            (lambda s: (s+':00') if (s and len(s)==5) else (s or '00:00:00'))(it.get("checkout_time") or ""),
                            it.get("hotel_name") or "",
                            it.get("adress") or it.get("address") or "",
                            float(it.get("total_amount") or 0) if str(it.get("total_amount") or "").strip() else 0.0,
                            bill_b
                        ])
                        grand_total += float(it.get("total_amount") or 0) if str(it.get("total_amount") or "").strip() else 0.0

            # (D) Food / DA
                if isinstance(da_entries, list) and da_entries:
                    with connection.cursor() as cur:
                        for it in da_entries:
                            if not isinstance(it, dict): continue
                            # compute number_days if missing
                            ndays = it.get("number_days")
                            try:
                                ndays = int(ndays)
                            except Exception:
                                ndays = 0
                            if not ndays:
                                fd = it.get("fromdate") or ""
                                td = it.get("todate") or ""
                                try:
                                    from datetime import date
                                    d1 = date.fromisoformat(fd) if fd else None
                                    d2 = date.fromisoformat(td) if td else None
                                    if d1 and d2:
                                        ndays = max(0, (d2 - d1).days + 1)
                                except Exception:
                                    ndays = 0
                            # compute amount from master if missing
                            amt_val = it.get("amount")
                            if amt_val in (None, "", "null", "None"):
                                rate = _travel_purpose_rate(t0.get("purpose_journey") or t0.get("purpose") or "")
                                amt_val = float(rate) * float(ndays or 0)
                            amt = float(amt_val or 0) if str(amt_val or "").strip() else 0.0
                            cur.execute("""
                                INSERT INTO food (travel_id, fromdate, todate, number_days, amount)
                                VALUES (%s,%s,%s,%s,%s)
                            """, [
                                travel_id,
                                it.get("fromdate") or None,
                                it.get("todate") or None,
                                ndays,
                                amt
                            ])
                            grand_total += amt

            # (E) Misc
            if isinstance(misc_entries, list) and misc_entries:
                with connection.cursor() as cur:
                    for it in misc_entries:
                        if not isinstance(it, dict): continue
                        amt = float(it.get("amount") or 0) if str(it.get("amount") or "").strip() else 0.0
                        bill_b = it.get("bill_photo")
                        if isinstance(bill_b, str):
                            bill_b = b64bytes(bill_b)
                        # Make bill optional for miscellaneous expenses
                        # if (amt>0 or (it.get('particulars') or it.get('perticulers'))) and not bill_b:
                        #     raise ValueError('Miscellaneous row is missing bill file.')
                        cur.execute("""
                            INSERT INTO miscellaneous_expenses (travel_id, uploaded_date, particulars, amount, bill_photo)
                            VALUES (%s,%s,%s,%s,%s)
                        """, [
                            travel_id,
                            it.get("date") or None,
                            it.get("perticulers") or it.get("particulars") or "",
                            amt,
                            bill_b
                        ])
                        grand_total += amt

            # Update voucher total if not provided
            with connection.cursor() as cur:
                cur.execute("UPDATE voucher SET total_amount=%s WHERE voucher_id=%s", [float(v0.get("total_amount") or grand_total), voucher_id])

        return _ok({
            "voucher_id": voucher_id,
            "travel_id": travel_id,
            "total_amount": float(v0.get("total_amount") or grand_total)
        }, status=201)

    except Exception as e:
        msg = str(e)
        if 'missing bill file' in msg.lower():
            return _err(msg, 400)
        return _err(f"DB error: {e}", 500)
from django.views.decorators.http import require_GET
from django.http import JsonResponse
from django.db import connection

@require_GET
def employees_list(request):
    """
    Return a simple list of employees to populate the 'Visit Authorised By' dropdown.
    Shape: [{ "emp_id": 1, "name": "Alice" }, ...]
    """
    with connection.cursor() as cur:
        cur.execute("""
            SELECT emp_id, name
            FROM employee
            WHERE name IS NOT NULL AND TRIM(name) <> ''
            ORDER BY name ASC
        """)
        rows = cur.fetchall()

    data = [{"emp_id": r[0], "name": r[1]} for r in rows]
    return JsonResponse(data, safe=False)

from django.views.decorators.http import require_GET
from django.http import JsonResponse, HttpResponseNotAllowed
from django.db import connection

def _current_emp_id(request):
    """Gets logged-in emp_id from session (set during login_api)."""
    auth = request.session.get("auth") or {}
    return int(auth.get("emp_id") or 0)

@require_GET
def api_validate_list(request):
    """
    Return the rows for Validate Voucher table that are assigned to THIS approver.
    Rule: voucher.status is the current stage (1..4). We pick approver{status}id from voucher_status
    and compare it with the logged-in emp_id.
    Columns required by the table: Employee Name, Voucher No, Voucher Type, Work Order, Total Amount.
    """
    emp_id = _current_emp_id(request)
    if not emp_id:
        return JsonResponse({"ok": False, "error": "Not logged in"}, status=401)

    # Build filter on approver id based on voucher.status value
    # status: 1→approver1id, 2→approver2id, 3→approver3id, 4→approver4id
    sql = """
        SELECT
            e.name              AS employee_name,
            DATE(v.upload_date) AS upload_date,
            v.voucher_id        AS voucher_no,
            UPPER(v.voucher_type) AS voucher_type,
            v.work_order_no     AS work_order_no,
            COALESCE(v.total_amount, 0) AS total_amount,
            CASE v.status
                WHEN 1 THEN vs.approver1
                WHEN 2 THEN vs.approver2
                WHEN 3 THEN vs.approver3
                WHEN 4 THEN vs.approver4
                ELSE NULL
            END AS stage_approved,
            CASE v.status
                WHEN 1 THEN vs.remarks1
                WHEN 2 THEN vs.remarks2
                WHEN 3 THEN vs.remarks3
                WHEN 4 THEN vs.remarks4
                ELSE NULL
            END AS stage_remarks
        FROM voucher v
        JOIN employee e         ON e.emp_id = v.emp_id
        JOIN voucher_status vs  ON vs.voucher_id = v.voucher_id
        WHERE
            CASE v.status
                WHEN 1 THEN vs.approver1id
                WHEN 2 THEN vs.approver2id
                WHEN 3 THEN vs.approver3id
                WHEN 4 THEN vs.approver4id
                ELSE NULL
            END = %s
          AND v.status BETWEEN 1 AND 4
        ORDER BY v.upload_date DESC, v.voucher_id DESC
    """
    with connection.cursor() as cur:
        cur.execute(sql, [emp_id])
        rows = cur.fetchall()

    data = [
        {
            "employee_name": r[0],
            "upload_date":   (r[1].isoformat() if hasattr(r[1], 'isoformat') else (str(r[1]) if r[1] is not None else "")),
            "voucher_no":    r[2],
            "voucher_type":  r[3],
            "work_order":    r[4],
            "total_amount":  float(r[5] or 0),
            "stage_approved": (str(r[6]).strip() if r[6] is not None else None),
            "stage_remarks":  (str(r[7]) if r[7] is not None else ""),
        }
        for r in rows
    ]
    return JsonResponse({"ok": True, "data": data})

@require_GET
def api_validate_details(request, voucher_id: str):
    """
    Return details blob for the modal:
      - Common: voucher_no, voucher_type, work_order, total_amount, employee_name
      - If type == PURCHASE → description, (we serve bill via your existing /files/... endpoint)
      - If type == EXPENSE  → expense_type list
      - If type == TRAVEL   → stitched summary from child tables (counts + sums)
    """
    try:
        # First, fetch header + type
        hdr_sql = """
            SELECT UPPER(v.voucher_type) AS vtype,
                   v.work_order_no,
                   COALESCE(v.total_amount,0),
                   e.name,
                   v.expense_date
            FROM voucher v
            JOIN employee e ON e.emp_id = v.emp_id
            WHERE v.voucher_id = %s
            LIMIT 1
        """
        with connection.cursor() as cur:
            cur.execute(hdr_sql, [voucher_id])
            row = cur.fetchone()
            if not row:
                return JsonResponse({"ok": False, "error": "Voucher not found"}, status=404)

            vtype, wo, total, empname, exp_date = row
            details = {"voucher_no": voucher_id, "voucher_type": vtype, "work_order": wo,
                       "total_amount": float(total or 0), "employee_name": empname,
                       "expense_date": (exp_date.isoformat() if hasattr(exp_date, 'isoformat') else (str(exp_date) if exp_date is not None else ""))}

            if vtype == "PURCHASE":
                cur.execute("""SELECT description FROM purchase WHERE voucher_id=%s LIMIT 1""", [voucher_id])
                r = cur.fetchone()
                details["purchase"] = {
                    "description": (r[0] if r else ""),
                    "bill_url": f"/api/files/purchase/voucher/{voucher_id}/",
                }

            elif vtype == "EXPENSE":
                cur.execute("""SELECT expense_id, expense_type, total_amount FROM expense WHERE voucher_id=%s""", [voucher_id])
                items = [{
                    "expense_id": int(rr[0]),
                    "expense_type": rr[1],
                    "amount": float(rr[2] or 0),
                    "file_url": f"/api/files/expense/{int(rr[0])}/",
                } for rr in cur.fetchall()]
                details["items"] = items

            elif vtype == "TRAVEL":
                # find travel_id
                cur.execute("""SELECT travel_id FROM travel WHERE voucher_id=%s LIMIT 1""", [voucher_id])
                rtid = cur.fetchone()
                travel_id = int(rtid[0]) if rtid else None
                if travel_id:
                    # Detailed rows + sums
                    cur.execute("SELECT travel_fare_id, from_place, to_place, mode_transport, COALESCE(cost,0) FROM travel_fare WHERE travel_id=%s", [travel_id])
                    fare_rows = [{
                        "id": int(rf[0]),
                        "from_place": rf[1], "to_place": rf[2],
                        "mode_transport": rf[3], "amount": float(rf[4] or 0),
                        "file_url": f"/api/files/travel_fare/{int(rf[0])}/",
                    } for rf in cur.fetchall()]

                    cur.execute("SELECT localfare_id, fromplace, toplace, mode_transport, number_km, COALESCE(amount,0) FROM local_fare WHERE travel_id=%s", [travel_id])
                    local_rows = [{
                        "id": int(rl[0]),
                        "from": rl[1], "to": rl[2],
                        "mode_transport": rl[3], "km": rl[4], "amount": float(rl[5] or 0),
                        "file_url": f"/api/files/local_fare/{int(rl[0])}/",
                    } for rl in cur.fetchall()]

                    cur.execute("SELECT hotel_acc_id, checkin_date, checkout_date, hotel_name, adress, COALESCE(total_amount,0) FROM hotel_accomodation WHERE travel_id=%s", [travel_id])
                    hotel_rows = [{
                        "id": int(rh[0]),
                        "checkin_date": rh[1],
                        "checkout_date": rh[2],
                        "hotel_name": rh[3], "address": rh[4], "amount": float(rh[5] or 0),
                        "file_url": f"/api/files/hotel/{int(rh[0])}/",
                    } for rh in cur.fetchall()]

                    cur.execute("SELECT food_id, fromdate, todate, number_days, COALESCE(amount,0) FROM food WHERE travel_id=%s", [travel_id])
                    food_rows = [{
                        "id": int(rf2[0]), "from_date": rf2[1], "to_date": rf2[2],
                        "days": int(rf2[3] or 0), "amount": float(rf2[4] or 0),
                    } for rf2 in cur.fetchall()]

                    cur.execute("SELECT miscel_expense_id, uploaded_date, particulars, COALESCE(amount,0) FROM miscellaneous_expenses WHERE travel_id=%s", [travel_id])
                    misc_rows = [{
                        "id": int(rm[0]), "date": rm[1], "particulars": rm[2], "amount": float(rm[3] or 0),
                        "file_url": f"/api/files/misc/{int(rm[0])}/",
                    } for rm in cur.fetchall()]

                    # Sums
                    def _sum_q(sql):
                        cur.execute(sql, [travel_id])
                        rr = cur.fetchone(); return float(rr[0] or 0)
                    details["travel"] = {
                        "fare":  {"rows": fare_rows,  "sum": _sum_q("SELECT COALESCE(SUM(cost),0) FROM travel_fare WHERE travel_id=%s")},
                        "local": {"rows": local_rows, "sum": _sum_q("SELECT COALESCE(SUM(amount),0) FROM local_fare WHERE travel_id=%s")},
                        "hotel": {"rows": hotel_rows, "sum": _sum_q("SELECT COALESCE(SUM(total_amount),0) FROM hotel_accomodation WHERE travel_id=%s")},
                        "food":  {"rows": food_rows,  "sum": _sum_q("SELECT COALESCE(SUM(amount),0) FROM food WHERE travel_id=%s")},
                        "misc":  {"rows": misc_rows,  "sum": _sum_q("SELECT COALESCE(SUM(amount),0) FROM miscellaneous_expenses WHERE travel_id=%s")},
                    }

        return JsonResponse({"ok": True, "data": details})
    except Exception as e:
        return _err(f"Failed to load details: {e}", 500)

@csrf_exempt
def api_validate_decision(request):
    """
    Decide on a voucher currently assigned to the logged-in approver.
    - Approve: set voucher_status.approver{seq} = '1' and bump voucher.status (+1 up to 5)
    - Reject:  require remarks (>=50 chars) and save into voucher_status.remarks{seq}
    Security: approver must match voucher_status.approver{seq}id for this voucher.
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    body, _files = _get_json_or_form(request)
    voucher_id = (body.get("voucher_id") or "").strip()
    decision   = (body.get("decision")   or "").strip().lower()
    remarks    = (body.get("remarks")    or "").strip()

    auth = request.session.get("auth") or {}
    emp_id = int(auth.get("emp_id") or 0)
    if not emp_id:
        return _err("Not logged in.", 401)
    if not voucher_id:
        return _err("voucher_id is required.", 400)
    if decision not in ("approve", "reject"):
        return _err('decision must be "approve" or "reject".', 400)

    # Find this approver's sequence (1..4)
    with connection.cursor() as cur:
        cur.execute("SELECT approve_seq FROM Credentials WHERE emp_id=%s LIMIT 1", [emp_id])
        row = cur.fetchone()
    if not row or row[0] is None:
        return _err("Your account is missing approve_seq.", 400)
    seq = int(row[0])
    if seq < 1 or seq > 4:
        return _err("approve_seq must be between 1 and 4.", 400)

    # Confirm voucher exists and is at this stage; confirm approver id matches chain
    with connection.cursor() as cur:
        cur.execute("SELECT COALESCE(status,0) FROM voucher WHERE TRIM(voucher_id)=TRIM(%s) LIMIT 1", [voucher_id])
        vrow = cur.fetchone()
    if not vrow:
        return _err("Voucher not found.", 404)

    # Ensure this user is indeed the assigned approver at this stage
    with connection.cursor() as cur:
        cur.execute(f"SELECT approver{seq}id FROM voucher_status WHERE voucher_id=%s LIMIT 1", [voucher_id])
        arow = cur.fetchone()
    if not arow:
        return _err("Approval route not initialized for this voucher.", 400)
    if int(arow[0] or 0) != emp_id:
        return _err("You are not the assigned approver for this stage.", 403)

    # Persist the decision (guard against duplicate submissions)
    try:
        with transaction.atomic():
            with connection.cursor() as cur:
                # Check current status and whether a decision already exists for this stage
                cur.execute(f"""
                    SELECT COALESCE(v.status,0) AS st, vs.approver{seq}, vs.remarks{seq}
                      FROM voucher v
                      JOIN voucher_status vs ON vs.voucher_id = v.voucher_id
                     WHERE v.voucher_id=%s
                     LIMIT 1
                """, [voucher_id])
                chk = cur.fetchone()
                if not chk:
                    return _err("Voucher not found.", 404)
                cur_status, cur_approved, cur_remarks = chk
                # If already approved/rejected at this stage, do not allow again
                if (str(cur_approved).strip() == '1') or (cur_remarks is not None and str(cur_remarks).strip() != ''):
                    return _err("Decision already recorded for this stage.", 409)
                # Ensure voucher is at this approver's stage
                if int(cur_status or 0) != int(seq):
                    return _err("Voucher is not at your stage for action.", 400)
                if decision == "approve":
                    # Mark approver{seq} = '1'
                    cur.execute(f"UPDATE voucher_status SET approver{seq}=%s WHERE voucher_id=%s", ["1", voucher_id])
                    # Increment status up to 5
                    cur.execute("""
                        UPDATE voucher
                           SET status = CASE WHEN COALESCE(status,0) < 5 THEN COALESCE(status,0) + 1 ELSE status END
                         WHERE voucher_id=%s
                    """, [voucher_id])
                else:  # reject
                    if len(remarks) < 50:
                        return _err("Remarks must be at least 50 characters.", 400)
                    cur.execute(f"UPDATE voucher_status SET remarks{seq}=%s WHERE voucher_id=%s", [remarks, voucher_id])
    except Exception as e:
        return _err(f"Database error: {e}", 500)

    return _ok({"voucher_id": voucher_id, "decision": decision, "stage": seq})

@require_GET
def api_my_vouchers(request):
    auth = request.session.get("auth") or {}
    emp_id = int(auth.get("emp_id") or 0)
    if not emp_id:
        return JsonResponse({"ok": False, "error": "Not logged in"}, status=401)

    with connection.cursor() as cur:
        cur.execute("""
            SELECT
                v.voucher_id,
                DATE(v.upload_date)               AS upload_date,
                COALESCE(v.total_amount,0)        AS total_amount,
                UPPER(v.voucher_type)             AS voucher_type,
                vs.approver1, vs.remarks1,
                vs.approver2, vs.remarks2,
                vs.approver3, vs.remarks3,
                vs.approver4, vs.remarks4
            FROM voucher v
            LEFT JOIN voucher_status vs ON vs.voucher_id = v.voucher_id
            WHERE v.emp_id = %s
            ORDER BY v.upload_date DESC, v.voucher_id DESC
        """, [emp_id])
        rows = cur.fetchall()

    def J(r):
        return {
            "voucher_id":   r[0],
            "upload_date":  r[1].isoformat() if r[1] else "",
            "total_amount": float(r[2] or 0),
            "voucher_type": r[3] or "",
            "approver1": r[4], "remarks1": r[5],
            "approver2": r[6], "remarks2": r[7],
            "approver3": r[8], "remarks3": r[9],
            "approver4": r[10], "remarks4": r[11],
        }
    return JsonResponse({"ok": True, "data": [J(r) for r in rows]})
