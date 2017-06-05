from django.conf.urls import patterns

urlpatterns = patterns('data_analytics_service.views',
    (r'^data_analytics_service_screen/$', 'data_analytics_service_screen'),
    (r'^start_or_stop_service/$', 'start_or_stop_service'),
    (r'^rerun_service/$', 'rerun_service')
)