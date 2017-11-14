from django.conf.urls import include, url
from django.contrib import admin
admin.autodiscover()
# add
import views as chartapi_views

urlpatterns = (
    # 'chartapi.views',
    # url(r'^query/$', 'mongodb_query', name='mongodb_query'),
    url(r'^tb_inc_status/$', chartapi_views.tb_inc_status, name='tb_inc_status'),
    url(r'^dbstatus/$', chartapi_views.dbstatus, name='dbstatus'),
)
