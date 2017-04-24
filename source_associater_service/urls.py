from django.conf.urls import patterns

urlpatterns = patterns('source_associater_service.views',
    (r'^source_associater_screen/$', 'source_associater_screen'),
    (r'^get_all_source_names/$', 'get_all_source_names'),
    (r'^associate_ips_to_sources/$', 'associate_ips_to_sources'),
)