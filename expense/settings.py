from pathlib import Path
import os

# expense/settings.py
import os
AES256_KEY_HEX = os.getenv("AES256_KEY_HEX", "4698804a4839b6f7fcb2f76b8ef48fba42299c81d79d553236abd81a317a3c73")

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-please-change-me-for-production'
DEBUG = True
ALLOWED_HOSTS = ['127.0.0.1', 'localhost','192.168.0.104']
CSRF_TRUSTED_ORIGINS = [
    'http://192.168.0.104',   # add https version too if you use it
]
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "login"   # change to 'dashboard' later if you have one
LOGOUT_REDIRECT_URL = "login"

ROOT_URLCONF = 'expense.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # Your templates are at core/templates/login.html, etc.
        'DIRS': [BASE_DIR / 'core' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'expense.wsgi.application'
ASGI_APPLICATION = 'expense.asgi.application'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.getenv("DB_NAME", "expense_db"),
        "USER": os.getenv("DB_USER", "expense_user"),
        "PASSWORD": os.getenv("DB_PASSWORD", "1234"),
        "HOST": os.getenv("DB_HOST", "127.0.0.1"),
        "PORT": os.getenv("DB_PORT", "3306"),
        "OPTIONS": {
            "charset": "utf8mb4",
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}

AUTH_PASSWORD_VALIDATORS = []
# Allow larger POST bodies (form fields + files)
DATA_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024   # 50 MB overall POST limit
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024    # Files >5MB stream to temp files
FILE_UPLOAD_HANDLERS = [
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
]
# (and ensure your MEDIA settings are configured)
# MEDIA_ROOT = BASE_DIR / "media"
# MEDIA_URL = "/media/"

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / "core" / "static"]

# (Optional but useful for file uploads API)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'uploads'
