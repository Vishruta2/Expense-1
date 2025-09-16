# core/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('auth/login/',  views.login_api,  name='api_login'),
    # path('auth/whoami/', views.whoami,     name='api_whoami'),
    path('auth/logout/', views.logout_api, name='api_logout'),
    path('vouchers/purchase/create/', views.api_create_purchase_voucher, name='api_create_purchase_voucher'),
    
    # path('files/purchase/voucher/<str:voucher_id>/', views.serve_purchase_bill_by_voucher),
    # path('files/purchase/id/<int:purchase_id>/',   views.serve_purchase_bill_by_id),

    path('files/purchase/voucher/<str:voucher_id>/', views.serve_purchase_bill_by_voucher, name='purchase_bill_by_voucher'),
    path('files/purchase/id/<int:purchase_id>/',   views.serve_purchase_bill_by_id,       name='purchase_bill_by_id'),
    # Additional file-serving routes for validation details
    path('files/expense/<int:expense_id>/',       views.serve_expense_bill_by_id,       name='expense_bill_by_id'),
    path('files/travel_fare/<int:travel_fare_id>/', views.serve_travel_fare_bill_by_id, name='travel_fare_bill_by_id'),
    path('files/local_fare/<int:local_fare_id>/', views.serve_local_fare_bill_by_id,     name='local_fare_bill_by_id'),
    path('files/hotel/<int:hotel_id>/',           views.serve_hotel_bill_by_id,          name='hotel_bill_by_id'),
    path('files/misc/<int:misc_id>/',             views.serve_misc_bill_by_id,           name='misc_bill_by_id'),

    path("auth/me/", views.api_auth_me, name="api_auth_me"),
    path("employees/managers/", views.api_managers_list, name="api_managers_list"),
    path("master/travel/", views.api_master_travel_lists, name="api_master_travel_lists"),

    # path("api/suppliers/", views.suppliers_list, name="suppliers-list"),
    # path("api/projects/", views.projects_list, name="projects-list"),
    path('suppliers/', views.suppliers_list, name='suppliers_list'),
    path('projects/',  views.projects_list,  name='projects_list'),

    path('projects/', views.projects_list),

    # Department Head: add/update projects (work order no)
    path('projects/upsert/', views.api_projects_upsert, name='api_projects_upsert'),
    path('projects/details/<str:work_order_no>/', views.api_project_details, name='api_project_details'),


    path('vouchers/expense/create/', views.api_create_expense_voucher, name='api_create_expense_voucher'),
    path("master/transport_modes/", views.api_master_transport_modes, name="api_master_transport_modes"),
    path("master/transport_modes/", views.api_master_transport_modes, name="api_master_transport_modes"),
    path("master/transport_mode/",  views.api_master_transport_modes),  # alias

    
    path('vouchers/travel/save/', views.api_save_travel_voucher, name='api_save_travel_voucher'),

    # Payment request APIs
    path('payment_request/create/', views.api_payment_request_create, name='api_payment_request_create'),
    path('payment_request/my/', views.api_payment_request_my_list, name='api_payment_request_my_list'),
    path('payment_request/pending/', views.api_payment_request_pending_list, name='api_payment_request_pending_list'),
    path('payment_request/decision/', views.api_payment_request_decision, name='api_payment_request_decision'),

    # Admin maintenance APIs
    path('admin/departments/', views.api_admin_department_list, name='api_admin_department_list'),
    path('admin/employees/', views.api_admin_employee_list, name='api_admin_employee_list'),
    path('admin/employee/upsert/', views.api_admin_employee_upsert, name='api_admin_employee_upsert'),
    path('admin/credentials/', views.api_admin_credentials_list, name='api_admin_credentials_list'),
    path('admin/credentials/upsert/', views.api_admin_credentials_upsert, name='api_admin_credentials_upsert'),
    path('master/travel/upsert/', views.api_master_travel_upsert, name='api_master_travel_upsert'),
    path('master/transport_mode/upsert/', views.api_master_transport_mode_upsert, name='api_master_transport_mode_upsert'),

    path('validate/list/',    views.api_validate_list,    name='api_validate_list'),
    path('validate/details/<str:voucher_id>/', views.api_validate_details, name='api_validate_details'),
    path('validate/decision/', views.api_validate_decision, name='api_validate_decision'),  # NEW
    path('vouchers/list/', views.api_my_vouchers, name='api_my_vouchers'),

]
