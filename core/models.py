from django.db import models

class Department(models.Model):
    dept_id = models.IntegerField(primary_key=True)
    dept_name = models.CharField(max_length=255)
    dept_type = models.CharField(max_length=255)
    dept_head = models.CharField(max_length=255)

    class Meta:
        managed = False
        db_table = 'Department'

class SupplierData(models.Model):
    supplier_id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=255)
    gstn_no = models.CharField(max_length=255)
    contact_no = models.BigIntegerField()
    contact_person = models.CharField(max_length=255)
    email_id = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    bank_name = models.CharField(max_length=255)
    bank_acc_no = models.CharField(max_length=255)
    ifsc_code = models.CharField(max_length=255)
    bank_branch = models.CharField(max_length=255)

    class Meta:
        managed = False
        db_table = 'SupplierData'

class Projects(models.Model):
    work_order_no = models.CharField(primary_key=True, max_length=255)
    project_name = models.CharField(max_length=255)
    client_name = models.CharField(max_length=255)
    project_type = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    dept = models.ForeignKey(Department, on_delete=models.PROTECT, db_column='dept_id')
    status = models.CharField(max_length=255)

    class Meta:
        managed = False
        db_table = 'Projects'

class Employee(models.Model):
    emp_id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=255)
    age = models.IntegerField()
    address = models.CharField(max_length=255)
    contact = models.BigIntegerField()
    email_id = models.CharField(max_length=255)
    dept = models.ForeignKey(Department, on_delete=models.PROTECT, db_column='dept_id')

    class Meta:
        managed = False
        db_table = 'Employee'

class Credentials(models.Model):
    cred_id = models.IntegerField(primary_key=True)
    role = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # Consider hashing; see note below
    emp = models.ForeignKey(Employee, on_delete=models.PROTECT, db_column='emp_id')

    class Meta:
        managed = False
        db_table = 'Credentials'

class Voucher(models.Model):
    voucher_id = models.CharField(primary_key=True, max_length=255)
    work_order_no = models.ForeignKey(Projects, on_delete=models.PROTECT, db_column='work_order_no')
    upload_date = models.DateField()
    expense_date = models.DateField()
    voucher_type = models.CharField(max_length=255)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    emp = models.ForeignKey(Employee, on_delete=models.PROTECT, db_column='emp_id')

    class Meta:
        managed = False
        db_table = 'Voucher'

class Purchase(models.Model):
    purchase_id = models.IntegerField(primary_key=True)
    supplier = models.ForeignKey(SupplierData, on_delete=models.PROTECT, db_column='supplier_id')
    voucher = models.ForeignKey(Voucher, on_delete=models.PROTECT, db_column='voucher_id')

    class Meta:
        managed = False
        db_table = 'Purchase'

class PurchaseItems(models.Model):
    item_id = models.IntegerField(primary_key=True)
    purchase = models.ForeignKey(Purchase, on_delete=models.CASCADE, db_column='purchase_id', related_name='items')
    material_name = models.CharField(max_length=255)
    qty = models.IntegerField()
    uom = models.CharField(max_length=255)
    amount_per_unit = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        managed = False
        db_table = 'PurchaseItems'
