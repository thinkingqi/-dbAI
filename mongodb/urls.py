from django.conf.urls import include, url
from django.contrib import admin
admin.autodiscover()
import views as mongodb_views

urlpatterns = (
    # 'mongodb.views',
    # url(r'^$', 'oms.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^query/$', mongodb_views.mongodb_query, name='mongodb_query'),
    url(r'^map/$', mongodb_views.map, name='map'),
)
