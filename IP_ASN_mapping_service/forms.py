from django import forms

class IPASNMappingServiceConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    is_running = forms.BooleanField(required=False,
                                    label="Is Running",
                                    initial=True)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(IPASNMappingServiceConfigForm, self).__init__(*args, **kwargs)