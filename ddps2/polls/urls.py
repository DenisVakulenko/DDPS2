from django.conf.urls import patterns, url

from polls import views

urlpatterns = patterns('',
    url(r'^$', views.index),
    url(r'^registration/$', views.registration),
    url(r'^login/$', views.login),
    url(r'^logout/$', views.logout),
    
    url(r'^test/$', views.test),
    url(r'^app/privatedata/$', views.app_privatedata),

    url(r'^oauth2/getgrant/$', views.oauth_grant),
    url(r'^oauth2/gettoken/$', views.oauth_token),
    url(r'^oauth2/test2/$', views.test2),
    url(r'^oauth2/getprivate/$', views.oauth_private),
    url(r'^oauth2/getpublic/$', views.oauth_public),

    url(r'^allsongs/$', views.allsongs),
    url(r'^allusers/$', views.allusers),
)