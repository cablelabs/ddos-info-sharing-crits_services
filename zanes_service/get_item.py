from django import template

register = template.Library()

#from django.template.defaulttags import register

@register.filter
def get_item(dictionary, key):
    # usage: {{ mydict|get_item:item }}
    return dictionary.get(key)