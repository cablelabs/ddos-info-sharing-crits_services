from django import forms

class DataIngesterServiceRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    choices = [('DNS', 'DNS'),
               ('Whois', 'Whois')]
    LookupType = forms.ChoiceField(required=True,
                                   label="Lookup Type",
                                   widget=forms.Select(),
                                   choices=choices)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(DataIngesterServiceRunForm, self).__init__(*args, **kwargs)