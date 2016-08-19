from django import forms

class ZanesServiceConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ZanesServiceConfigForm, self).__init__(*args, **kwargs)

class ZanesServiceRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    Vendor = forms.IntegerField(required=True,
                                label="Vendor",
                                widget=forms.NumberInput())
    FirstSeen = forms.CharField(required=True,
                                label="FirstSeen",
                                widget=forms.TextInput())
    LastSeen = forms.CharField(required=True,
                               label="LastSeen",
                               widget=forms.TextInput())
    NumberOfTimes = forms.IntegerField(required=True,
                                       label="NumberOfTimes",
                                       widget=forms.NumberInput())
    City = forms.CharField(required=True,
                           label="City",
                           widget=forms.TextInput())
    State = forms.CharField(required=True,
                            label="State",
                            widget=forms.TextInput())
    Country = forms.CharField(required=True,
                              label="Country",
                              widget=forms.TextInput())
    TotalBPS = forms.IntegerField(required=True,
                                  label="TotalBPS",
                                  widget=forms.NumberInput())
    TotalPPS = forms.IntegerField(required=True,
                                  label="TotalPPS",
                                  widget=forms.NumberInput())
    ASN = forms.CharField(required=True,
                          label="ASN",
                          widget=forms.TextInput())
    Type = forms.CharField(required=True,
                           label="Type",
                           widget=forms.TextInput())
    AlertType = forms.CharField(required=True,
                                label="AlertType",
                                widget=forms.TextInput())
    NumberFields = ['Vendor', 'NumberOfTimes', 'TotalBPS', 'TotalPPS']

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ZanesServiceRunForm, self).__init__(*args, **kwargs)

        for field in self.fields:
            if field not in self.data:
                if field not in self.NumberFields:
                    # initial value when viewing in web browser
                    self.fields[field].initial = ''
                    # value that gets saved to the info section of a run
                    self.data[field] = ''
                else:
                    self.fields[field].initial = 0
                    self.data[field] = 0
            elif isinstance(self.data[field], list):
                # The field's value is saved as singleton list for some reason.
                self.data[field] = self.data[field][0]

        #self.fields['money'].initial = True
        #self.data['money'] = 1