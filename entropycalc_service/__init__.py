# (c) 2013, Adam Polkosnik, <adam.polkosnik@ny.frb.org>
# Permission is granted for inclusion/distribution by The MITRE Corporation.
# All rights reserved.
# Source code distributed pursuant to license agreement.

import array
import math

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

class EntropycalcService(Service):
    """
    Calculate entropy over data.
    """

    name = "entropycalc"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Calculate entropy of a sample."

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values are submitted as a list for some reason.
        data = {'start': config['start'][0], 'end': config['end'][0]}
        return forms.EntropyCalcRunForm(data)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.EntropyCalcRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    def _calculate_entropy(self, data):
	entropy = 0.0
        if len(data) == 0:
            return entropy

        occurences = array.array('L', [0]*256)

        for x in data:
            occurences[ord(x)] += 1

        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy


    def scan(self, obj, config):
        start = config['start']
        end = config['end']
        data = obj.filedata.read()
	output = self._calculate_entropy(data[start:end])
        self._add_result('Entropy calculation', "%.1f" % output, {'Value': output})
