from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns(
    'monitor.views',
    # url(r'^$', 'oms.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^mon_set/$', 'mon_set', name='mon_set'),
    url(r'^mysql_status/$', 'mysql_status', name='mysql_status'),
    url(r'^mon_edit/$', 'mon_edit', name='mon_edit'),
    url(r'^mon_delete/$', 'mon_delete', name='mon_delete'),
    url(r'^batch_add/$', 'batch_add', name='batch_add'),
    # url(r'^test_tb/$', 'test_tb', name='test_tb'),
)

