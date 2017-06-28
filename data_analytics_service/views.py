import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext
from crits.core.user_tools import user_can_view_data

from . import handlers


@user_passes_test(user_can_view_data)
def data_analytics_service_screen(request):
    return render_to_response('data_analytics_service_screen.html',
                              {'process_status': handlers.process_status()},
                              RequestContext(request))


@user_passes_test(user_can_view_data)
def start_or_stop_service(request):
    if request.method == "POST" and request.is_ajax():
        results = handlers.start_or_stop_service()
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    return render_to_response('error.html',
                              {'error': "Must be POST and AJAX."},
                              RequestContext(request))


@user_passes_test(user_can_view_data)
def rerun_service(request):
    if request.method == "POST" and request.is_ajax():
        results = handlers.rerun_service()
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    return render_to_response('error.html',
                              {'error': "Must be POST and AJAX."},
                              RequestContext(request))
