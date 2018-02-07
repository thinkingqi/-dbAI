"""
Django settings for mypro project.

Generated by 'django-admin startproject' using Django 1.10.1.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.10/ref/settings/
"""
from __future__ import absolute_import
import os
import djcelery
from kombu import Queue,Exchange
djcelery.setup_loader()
BROKER_URL = 'redis://192.168.46.105:6379/0'
CELERYBEAT_SCHEDULER = 'djcelery.schedulers.DatabaseScheduler'
CELERY_IMPORTS = ("myapp.tasks","myapp.include.scheduled","myapp.include.mon")
CELERY_QUEUES = (
    Queue('default',Exchange('default'),routing_key='default'),
    Queue('mysql_monitor',Exchange('monitor'),routing_key='monitor.mysql'),
)
CELERY_ROUTES = {
    'myapp.include.mon.mon_mysql':{'queue':'mysql_monitor','routing_key':'monitor.mysql'},
    'myapp.include.mon.check_mysql_host': {'queue': 'mysql_monitor', 'routing_key': 'monitor.mysql'},
    'myapp.include.mon.sendmail_monitor': {'queue': 'mysql_monitor', 'routing_key': 'monitor.mysql'},
}
CELERY_DEFAULT_QUEUE = 'default'
CELERY_DEFAULT_EXCHANGE_TYPE = 'direct'
CELERY_DEFAULT_ROUTING_KEY = 'default'

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'f+3(9rok*aj*2a$^k3cn3bm^k4-!)8emv%qbuva(9yb^u&51kv'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

 ##
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # 'django_crontab',
    'captcha',
    'salt',
    'mongodb',
    'chartapi',
    'monitor',
    'passforget',
    'blacklist',
    'djcelery',
    'myapp',
]

# CRONJOBS = [
#     ('*/1 * * * *', 'myapp.scheduled.task_sche_run','>> /tmp/last_scheduled_job.log'),
#     ('30 0 * * *', 'myapp.scheduled.table_check','>> /tmp/scheduled_check_job.log'),
#
# ]


MIDDLEWARE_CLASSES = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'myapp.mymiddleware.expiretimeset',
]

ROOT_URLCONF = 'mypro.urls'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')]
        ,
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

WSGI_APPLICATION = 'mypro.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.10/ref/settings/#databases

#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#    }
#}

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'django',
        'USER': 'xxxx',
        'PASSWORD': 'xxxx',
        'HOST': 'xxxxx',
        'PORT': '3306',
        'OPTIONS': {
            #'init_command': 'SET default_storage_engine=INNODB',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"
        }
    }
}

# Password validation
# https://docs.djangoproject.com/en/1.10/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Shanghai'
DATETIME_FORMAT = 'Y-m-d H:i:s'
USE_I18N = True

USE_L10N = False

USE_TZ = True
#session
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE  = True
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/

#yanzhengma
#CAPTCHA_CHALLENGE_FUNCT = 'captcha.helpers.random_char_challenge'
#CAPTCHA_CHALLENGE_FUNCT = 'captcha.helpers.math_challenge'
#2minutes timeout
CAPTCHA_LETTER_ROTATION=(-10,20)
# CAPTCHA_NOISE_FUNCTIONS=('captcha.helpers.noise_dots',)
CAPTCHA_TIMEOUT=2
CAPTCHA_LENGTH=4
CAPTCHA_FONT_SIZE=24
CAPTCHA_BACKGROUND_COLOR='#FFFFFF'
CAPTCHA_FOREGROUND_COLOR='#000010'
CAPTCHA_OUTPUT_FORMAT=u'%(text_field)s %(image)s %(hidden_field)s'

STATIC_URL = '/static/'
STATICFILES_DIRS = (
os.path.join(BASE_DIR, "static"),
)
# STATIC_ROOT = os.path.join(BASE_DIR, 'static').replace('\\','/')
#MEDIA_ROOT = os.path.join(BASE_DIR, 'media').replace('\\','/')
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'


EMAIL_HOST='xxx'
EMAIL_HOST_USER='xxx'
EMAIL_HOST_PASSWORD='xxx'
EMAIL_PORT = 25
EMAIL_SENDER = 'xxxx'

DEFAULT_FROM_MAIL = EMAIL_HOST_USER
# EMAIL_USE_TLS = True
# URL_FOR_PASSWD = 'http://192.168.70.128:8000'
URL_FOR_PASSWD = 'http://127.0.0.1:8000'

# SaltStack API
SALT_API_URL = 'http://10.x.xx.xx:xx'
SALT_API_USER = 'saltapi'
SALT_API_PASSWD = 'saltapi'

SALT_DATABASE = {
    'NAME': 'salt',
    'USER': 'salt_user',
    'PASSWORD': 'xxx',
    'HOST': 'xx.xx.xx.xx',
    'PORT': 'xx',
}
