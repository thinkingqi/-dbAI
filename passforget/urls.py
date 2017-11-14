from django.conf.urls import include, url
from django.contrib import admin
admin.autodiscover()
# add
import views as passforget_views

urlpatterns = (
    # 'passforget.views',
    url(r'^pass_forget/$', passforget_views.pass_forget, name='pass_forget'),
    url(r'^pass_rec/$', passforget_views.pass_rec, name='pass_rec'),
)

