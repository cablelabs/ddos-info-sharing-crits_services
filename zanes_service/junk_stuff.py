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
        who_was_it = config.get('who_was_it', '')

        #if (not config['who_was_it']):
        if (not who_was_it):
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
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.ZanesServiceRunForm(money=config['money']),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'money' not in config:
            config['money'] = 0
        #form = forms.ZanesServiceRunForm(money=config['money'])
        #return form
        data = {'money': config['money']}
        return forms.ZanesServiceRunForm(data);

    # @staticmethod
    # def save_runtime_config(config):
    #    if config['money']:
    #        del config['money']



    # KEEP ALL CODE BELOW!
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