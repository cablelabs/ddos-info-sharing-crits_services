from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^source_associater_screen/$', views.source_associater_screen, name='source_associater_service-views-source_associater_screen'),
    url(r'^get_all_source_names/$', views.get_all_source_names, name='source_associater_service-views-get_all_source_names'),
    url(r'^associate_ips_to_sources/$', views.associate_ips_to_sources, name='source_associater_service-views-associate_ips_to_sources'),
]
