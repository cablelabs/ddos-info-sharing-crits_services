from django import forms

class ZanesServiceConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    who_was_it = forms.CharField(required=False,
                                 label="Who was it?",
                                 widget=forms.TextInput(),
                                 help_text="You thought it would be Jojo,",
                                 initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ZanesServiceConfigForm, self).__init__(*args, **kwargs)

class ZanesServiceRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    money = forms.IntegerField(required=True,
                               label="Money",
                               widget=forms.NumberInput(),
                               help_text="Give me some money!")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ZanesServiceRunForm, self).__init__(*args, **kwargs)

        self.fields['money'].initial = True
        self.data['money'] = 1