from crits.services.core import Service
from django.template.loader import render_to_string

from . import forms

class IPASNMappingService(Service):
    name = "IP_ASN_mapping_service"
    version = '0.0.1'
    template = None
    supported_types = []
    description = "A service that maps IP addresses to the ASN of the network they belong to."

    def run(self, obj, config):
        pass

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.IPASNMappingServiceConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        pass

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.IPASNMappingServiceConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.IPASNMappingServiceConfigForm(initial=config),
                                 'config_error': None})
        form = forms.IPASNMappingServiceConfigForm
        return form, html