from django.conf.urls import include, url
from django.contrib import admin
admin.autodiscover()
# add
import views as blacklist_views

urlpatterns = (
    # 'blacklist.views',
    url(r'^blist/$', blacklist_views.blist, name='blist'),
    url(r'^bl_delete/$', blacklist_views.bl_delete, name='bl_delete'),
    url(r'^bl_edit/$', blacklist_views.bl_edit, name='bl_edit'),
)
