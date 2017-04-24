import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext
from crits.core.user_tools import user_can_view_data

import handlers

@user_passes_test(user_can_view_data)
def source_associater_screen(request):
    return render_to_response('source_associater_screen.html',
                              {},
                              RequestContext(request))

@user_passes_test(user_can_view_data)
def get_all_source_names(request):
    if request.method == "GET" and request.is_ajax():
        all_source_names = handlers.get_all_source_names()
        output = {
            'success': True,
            'html': '',
            'source_names': all_source_names
        }
        return HttpResponse(json.dumps(output),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be GET and AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def associate_ips_to_sources(request):
    if request.method == "POST" and request.is_ajax():
        source_name = request.POST.get('source_name', None)
        result = handlers.associate_ips_to_sources(source_name)
        if result:
            message = "Success!"
        else:
            message = "Failure!"
        output = {
            'success': result,
            'html': '',
            'message': message
        }
        return HttpResponse(json.dumps(output),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be POST and AJAX."},
                                  RequestContext(request))