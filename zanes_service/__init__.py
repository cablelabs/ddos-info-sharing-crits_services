from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from . import forms

class ZanesService(Service):
    """
    A service made by me, Zane.
    """

    # Note: Using captial letters in 'name' somehow prevented CRITs
    # from associating the HTML tab file(s) with this service, even
    # when 'id' of the appropriate div was equal to 'name'.
    name = "zanes_service"
    version = '1.0.0'
    supported_types = ['IP']
    template = 'zanes_service_template.html'
    description = "A service made by me, Zane. What it actually does I'm not sure."
    NumberFields = ['Vendor', 'NumberOfTimes', 'TotalBPS', 'TotalPPS']

    def _scan(self, obj):
        pass

    def stop(self):
        pass

    def run(self, obj, config):
        pass
        #sum = 0;
        #for field in self.NumberFields:
        #    if config[field]:
        #        sum += config[field]
        #self._add_result("Number", "Sum", data={"Sum" : sum})


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
        pass

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
        #if 'money' not in config:
        #    config['money'] = 0;

        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.ZanesServiceRunForm(),#money_input=config['money']),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def bind_runtime_form(analyst, config):
        return forms.ZanesServiceRunForm(data=config)

    # @staticmethod
    # def save_runtime_config(config):
    #    if config['money']:
    #        del config['money']