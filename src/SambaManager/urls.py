from django.conf.urls.defaults import *
from django.http import HttpResponseRedirect

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

def redirect(request):
    return HttpResponseRedirect('/manager/')
    
urlpatterns = patterns('',
    # Example:
    # (r'^SambaManager/', include('SambaManager.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
    (r'^$', redirect),
    (r'^manager/', include('SambaManager.manager.urls')),
)
