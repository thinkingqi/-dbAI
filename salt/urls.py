#from django.conf.urls import patterns, include, url
from django.conf.urls import include, url
from django.contrib import admin
admin.autodiscover()
# add
import views as salt_views

# urlpatterns = patterns(
#     'salt.views',
#     # url(r'^$', 'oms.views.home', name='home'),
#     # url(r'^blog/', include('blog.urls')),
#     url(r'^api/execute$', 'execute', name='execute'),
#     url(r'^salt_exec/$', 'salt_exec', name='salt_exec'),
#     url(r'^hardware_info/$', 'hardware_info', name='hardware_info'),
#     url(r'^api/getjobinfo$','getjobinfo', name='getjobinfo'),
#     url(r'^key_con/$','key_con', name='key_con'),
#     url(r'^hist_salt/$','hist_salt', name='hist_salt'),
#     url(r'^record_detail/$','record_detail', name='record_detail'),
# )


urlpatterns = (
    # ##'salt.views',
    # url(r'^$', 'oms.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^api/execute$', salt_views.execute, name='execute'),
    url(r'^salt_exec/$', salt_views.salt_exec, name='salt_exec'),
    url(r'^hardware_info/$', salt_views.hardware_info, name='hardware_info'),
    url(r'^api/getjobinfo$',salt_views.getjobinfo, name='getjobinfo'),
    url(r'^key_con/$',salt_views.key_con, name='key_con'),
    url(r'^hist_salt/$',salt_views.hist_salt, name='hist_salt'),
    url(r'^record_detail/$',salt_views.record_detail, name='record_detail'),
)