# core/forms.py
from django import forms

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

class MultiFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True

class CredentialsForm(forms.Form):
    cred_id  = forms.IntegerField(min_value=1)
    role     = forms.CharField(max_length=64)
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned

class DepartmentForm(forms.Form):
    dept_id   = forms.IntegerField(min_value=1)
    dept_name = forms.CharField(max_length=255)
    dept_type = forms.CharField(max_length=255, required=False)
    dept_head = forms.CharField(max_length=255, required=False)

class EmployeeSecureForm(forms.Form):
    emp_id   = forms.IntegerField(min_value=1)
    name     = forms.CharField(max_length=255)
    age      = forms.IntegerField(required=False, min_value=0)
    address  = forms.CharField(max_length=255, required=False)
    contact  = forms.CharField(max_length=50, required=False)
    email_id = forms.EmailField(required=False)
    dept_id  = forms.IntegerField(min_value=1)

class SupplierForm(forms.Form):
    supplier_id    = forms.IntegerField(min_value=1)
    name           = forms.CharField(max_length=255)
    gstn_no        = forms.CharField(max_length=255, required=False)
    contact_no     = forms.CharField(max_length=20, required=False)
    contact_person = forms.CharField(max_length=255, required=False)
    email_id       = forms.EmailField(required=False)
    address        = forms.CharField(max_length=255, required=False)
    bank_name      = forms.CharField(max_length=255, required=False)
    bank_acc_no    = forms.CharField(max_length=255, required=False)
    ifsc_code      = forms.CharField(max_length=50, required=False)
    bank_branch    = forms.CharField(max_length=255, required=False)

class ProjectForm(forms.Form):
    work_order_no = forms.CharField(max_length=255)
    project_name  = forms.CharField(max_length=255)
    client_name   = forms.CharField(max_length=255, required=False)
    project_type  = forms.CharField(max_length=255, required=False)
    address       = forms.CharField(max_length=255, required=False)
    dept_id       = forms.IntegerField(min_value=1)
    status        = forms.CharField(max_length=255, required=False)

class VoucherForm(forms.Form):
    voucher_id   = forms.CharField(max_length=255)
    work_order_no= forms.CharField(max_length=255)
    upload_date  = forms.DateField(input_formats=["%Y-%m-%d"])
    expense_date = forms.DateField(input_formats=["%Y-%m-%d"])
    voucher_type = forms.CharField(max_length=255, required=False)
    total_amount = forms.DecimalField(max_digits=10, decimal_places=2, required=False)
    emp_id       = forms.IntegerField(min_value=1)

class PurchaseForm(forms.Form):
    purchase_id = forms.IntegerField(min_value=1)
    supplier_id = forms.IntegerField(min_value=1)
    voucher_id  = forms.CharField(max_length=255)

class PurchaseItemForm(forms.Form):
    item_id         = forms.IntegerField(min_value=1)
    material_name   = forms.CharField(max_length=255)
    qty             = forms.IntegerField(min_value=0)
    uom             = forms.CharField(max_length=50, required=False)
    amount_per_unit = forms.DecimalField(max_digits=10, decimal_places=2, required=False)
    total_amount    = forms.DecimalField(max_digits=10, decimal_places=2, required=False)

class VoucherFilesForm(forms.Form):
    voucher_id = forms.CharField(max_length=255)
    files = forms.FileField(widget=MultiFileInput(), required=True)