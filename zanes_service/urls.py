from django.conf.urls import url, patterns
from .views import get_zanes_service_data, update_ip_misc
from crits.core.views import update_object_description

#urlpatterns = patterns('zanes_service.views',
#    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_zanes_service_data'),
#)

# Making URLs like above is deprecated since Django 1.8+.

urlpatterns = [
    url(r'^update_object_description/', update_object_description, name='update_object_description'),
    url(r'^update_ip_misc/', update_ip_misc, name='update_ip_misc'),
    url(r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', get_zanes_service_data, name="get_zanes_service_data")
]