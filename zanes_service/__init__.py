from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from . import forms

class ZanesService(Service):
    """
    A service made by me, Zane.
    """

    name = "Zanes_Service"
    version = '1.0.0'
    supported_types = ['IP']
    template = 'zanes_service_template.html'
    description = "A service made by me, Zane. What it actually does I'm not sure."

    def run(self, obj, config):
        pass

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.ZanesServiceConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if (not config['who_was_it']):
            raise ServiceConfigError("who_was_it required.")

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.ZanesServiceConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ZanesServiceConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ZanesServiceConfigForm
        return form, html

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        if 'money' not in config:
            config['money'] = 0;
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.ZanesServiceRunForm(money_input=config['money']),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'money' not in config:
            config['money'] = 0
        elif isinstance(config['money'], list):
            # 'money' field is usually given as a list with one item for some reason.
            config['money'] = config['money'][0]
        form = forms.ZanesServiceRunForm(data=config)
        return form

    # @staticmethod
    # def save_runtime_config(config):
    #    if config['money']:
    #        del config['money']