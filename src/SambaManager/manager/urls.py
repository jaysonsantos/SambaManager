from django.conf.urls.defaults import *
from SambaManager.manager import views

urlpatterns = patterns('',
    # Example:
    # (r'^SambaManager/', include('SambaManager.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
    (r'^$', views.index),
    (r'login/$', views.login),
    (r'logout/$', views.logout),
    (r'add-user/$', views.add_user),
    (r'list-users/$', views.list_users),
    (r'edit-user/(?P<id>\d+)/$', views.edit_user),
    (r'delete-user/(?P<id>\d+)/$', views.delete_user),
    (r'add-group/$', views.add_group),
    (r'list-groups/$', views.list_groups),
    (r'delete-group/(?P<id>\d+)/$', views.delete_group),
    (r'add-share/$', views.add_share),
    (r'edit-share/(?P<id>\d+)/$', views.edit_share),
    (r'list-shares/$', views.list_shares),
    (r'delete-share/(?P<id>\d+)/$', views.delete_share),
)