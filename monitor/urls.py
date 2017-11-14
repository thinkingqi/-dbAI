from django.conf.urls import include, url
from django.contrib import admin
admin.autodiscover()
# add
import views as monitor_views

urlpatterns = (
    # 'monitor.views',
    # url(r'^$', 'oms.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^mon_set/$', monitor_views.mon_set, name='mon_set'),
    url(r'^mysql_status/$', monitor_views.mysql_status, name='mysql_status'),
    url(r'^mon_edit/$', monitor_views.mon_edit, name='mon_edit'),
    url(r'^mon_delete/$', monitor_views.mon_delete, name='mon_delete'),
    url(r'^batch_add/$', monitor_views.batch_add, name='batch_add'),
    # url(r'^test_tb/$', 'test_tb', name='test_tb'),
)

