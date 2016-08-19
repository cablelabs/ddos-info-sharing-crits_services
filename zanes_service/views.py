import HTMLParser
import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext

from crits.core.class_mapper import class_from_id, class_from_type, key_descriptor_from_obj_type
from crits.core.user_tools import user_can_view_data, user_sources

try:
    from mongoengine.base import ValidationError
except ImportError:
    from mongoengine.errors import ValidationError

from . import handlers

@user_passes_test(user_can_view_data)
def get_zanes_service_data(request, ctype, cid):
    result = { "success": "false", "message": "No data available." }

    sources = user_sources("%s" % request.user)
    if not sources:
        return HttpResponse(json.dumps(result), content_type="application/json")

    data = handlers.execute_data_get(sources)
    # If any of the values are not an empty string we have data.
    for v in data.values():
        if v != "":
            result['success'] = "true"
            result['message'] = data
            break

    return HttpResponse(json.dumps(result), content_type="application/json")


@user_passes_test(user_can_view_data)
def update_ip_misc(request):
    """
    Update misc in an IP object.

    :param request: Django request.
    :type request: :class:`django.http.HttpRequest`
    :returns: :class:`django.http.HttpResponse`
    """

    if request.method == "POST" and request.is_ajax():
        type_ = request.POST['type']
        id_ = request.POST['id']
        misc = request.POST['misc']
        analyst = request.user.username

        # next steps similar to misc_update() in code I hacked together.
        # Why does the original code separate these? Seems to make things more confusing.
        klass = class_from_type(type_)
        if not klass:
            return {'success': False, 'message': 'Could not find object.'}

        if hasattr(klass, 'source'):
            sources = user_sources(analyst)
            obj = klass.objects(id=id_, source__name__in=sources).first()
        else:
            obj = klass.objects(id=id_).first()
        if not obj:
            return {'success': False, 'message': 'Could not find object.'}

        # Have to unescape the submitted data. Use unescape() to escape
        # &lt; and friends. Use urllib2.unquote() to escape %3C and friends.
        h = HTMLParser.HTMLParser()
        misc = h.unescape(misc)
        update_result = {'success': True, 'message': "Misc set."}
        try:
            obj.misc = misc
            obj.save(username=analyst)
        except ValidationError, e:
            return {'success': False, 'message': e}

        return HttpResponse(json.dumps(update_result),
                            content_type="application/json")
    else:
        return render_to_response("error.html",
                                  {"error" : 'Expected AJAX POST.'},
                                  RequestContext(request))