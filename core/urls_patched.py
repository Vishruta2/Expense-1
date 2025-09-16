# from django.contrib import admin
# from django.urls import path, include
# from django.views.generic import TemplateView

# urlpatterns = [
    path('api/master/travel/rate/', core_views.api_master_food_rate, name='api_master_food_rate'),
#     path('admin/', admin.site.urls),
#     path('api/', include('core.urls')),                       # APIs
#     path('', TemplateView.as_view(template_name='login.html'))# login page at /
# ]

from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from core import views as core_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('api/master/travel/rate/', core_views.api_master_food_rate, name='api_master_food_rate'),
    path('admin/', admin.site.urls),
    path('api/', include('core.urls')),                       # APIs
    path('', TemplateView.as_view(template_name='login.html')),# login page at /
    path('employee-dashboard/', core_views.employee_dashboard, name='employee_dashboard'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
