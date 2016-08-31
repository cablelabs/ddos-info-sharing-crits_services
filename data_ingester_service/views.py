import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext
from crits.core.user_tools import user_can_view_data


@user_passes_test(user_can_view_data)
def data_ingester_query(request):
    return render_to_response('data_ingester_query.html',
                              {'foo': "bar"},
                              RequestContext(request))

@user_passes_test(user_can_view_data)
def get_service_data(request):
    if request.method == "POST" and request.is_ajax():
        results = {"foo" : "bar"}
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))