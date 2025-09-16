from rest_framework import serializers
from .models import (
    Department, SupplierData, Projects, Employee, Credentials,
    Voucher, Purchase, PurchaseItems
)

class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'

class SupplierDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupplierData
        fields = '__all__'

class ProjectsSerializer(serializers.ModelSerializer):
    # Accept dept_id directly in payload
    dept_id = serializers.IntegerField(write_only=True)
    class Meta:
        model = Projects
        fields = ['work_order_no','project_name','client_name','project_type','address','dept_id','status']

    def create(self, validated_data):
        dept_id = validated_data.pop('dept_id')
        validated_data['dept_id'] = dept_id  # use db_column
        return Projects.objects.create(**validated_data)

class EmployeeSerializer(serializers.ModelSerializer):
    dept_id = serializers.IntegerField(write_only=True)
    class Meta:
        model = Employee
        fields = ['emp_id','name','age','address','contact','email_id','dept_id']

    def create(self, validated_data):
        dept_id = validated_data.pop('dept_id')
        validated_data['dept_id'] = dept_id
        return Employee.objects.create(**validated_data)

class CredentialsSerializer(serializers.ModelSerializer):
    emp_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Credentials
        fields = ['cred_id','role','username','password','emp_id']

    def create(self, validated_data):
        # NOTE: consider hashing password before save
        emp_id = validated_data.pop('emp_id')
        validated_data['emp_id'] = emp_id
        return Credentials.objects.create(**validated_data)

class VoucherSerializer(serializers.ModelSerializer):
    work_order_no = serializers.CharField()
    emp_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Voucher
        fields = [
            'voucher_id','work_order_no','upload_date','expense_date',
            'voucher_type','total_amount','emp_id'
        ]

    def create(self, validated_data):
        emp_id = validated_data.pop('emp_id')
        validated_data['emp_id'] = emp_id
        # work_order_no is a FK on the model (handled automatically by ORM using string pk)
        return Voucher.objects.create(**validated_data)

class PurchaseItemInlineSerializer(serializers.ModelSerializer):
    class Meta:
        model = PurchaseItems
        fields = ['item_id','material_name','qty','uom','amount_per_unit','total_amount']

class PurchaseCreateSerializer(serializers.ModelSerializer):
    # accept FK ids directly
    supplier_id = serializers.IntegerField(write_only=True)
    voucher_id = serializers.CharField(write_only=True)
    items = PurchaseItemInlineSerializer(many=True)

    class Meta:
        model = Purchase
        fields = ['purchase_id','supplier_id','voucher_id','items']

    def create(self, validated_data):
        items_data = validated_data.pop('items', [])
        supplier_id = validated_data.pop('supplier_id')
        voucher_id = validated_data.pop('voucher_id')

        purchase = Purchase.objects.create(
            supplier_id=supplier_id,
            voucher_id=voucher_id,
            **validated_data
        )

        for item in items_data:
            PurchaseItems.objects.create(purchase=purchase, **item)

        return purchase

class PurchaseReadSerializer(serializers.ModelSerializer):
    items = PurchaseItemInlineSerializer(many=True, read_only=True)

    class Meta:
        model = Purchase
        fields = ['purchase_id', 'supplier', 'voucher', 'items']
