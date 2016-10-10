import os
import time
import commands
from ipwhois import IPWhois

from django.template.loader import render_to_string

from crits.services.core import Service
from . import forms

class DataIngesterService(Service):
    name = "data_ingester_service"
    version = '0.0.1'
    template = 'data_ingester_service_template.html'
    supported_types = ['IP']
    description = "A service that receives data from MSOs through POST messages."

    def __init(self):
        Service.__init__(self)
        number = 0
        while number < 10:
            print(number)
            number += 1
            if number >= 10:
                number = 0

    def run(self, obj, config):
        LookupType = config['LookupType']
        number = 0
        while number < 100:
            print(number)
            number += 1
            if number >= 100:
                number = 0
        if LookupType == 'DNS':
            self.DNSLookup(obj.ip, obj.ip_type)
        else: # Whois
            self.WhoisLookup(obj.ip)

    def DNSLookup(self, ip, ip_type):
        ip_numbers = ip.split('.')
        # need to reverse the sections of the IP in order to make the correct request for this IP
        ip_numbers.reverse()
        reversed_ip = '.'.join(ip_numbers)

        start_time = time.time()
        if ip_type == 'IPv4 Address':
            output = commands.getstatusoutput("dig +short " + reversed_ip + ".origin.asn.shadowserver.org TXT")
        else:
            #TODO Figure out how to convert IPv6 address to 'nibble' format. Also, not sure if Shadowserver URL similar.
            output = commands.getstatusoutput("dig +short " + reversed_ip + ".origin6.asn.cymru.com TXT")
        asn = self.GetASNFromOutput(output)
        duration = time.time() - start_time

        data = {
            'ASN': asn,
            'Lookup_Time': duration
        }
        self._add_result('DNS Lookup', 'DNS Lookup', data=data)

    def GetASNFromOutput(self, output):
        asn = output[1].split("|", 1)[0]      # ASN is the first value
        return asn.strip().replace("\"", "")  # remove extra characters

    def WhoisLookup(self, ip):
        command_string = "whois -h asn.shadowserver.org origin " + ip

        start_time = time.time()
        output = commands.getstatusoutput(command_string)
        duration = time.time() - start_time

        asn = self.GetASNFromWhoisOutput(output)
        data = {
            'ASN': asn,
            'Lookup_Time': duration
        }
        self._add_result('Whois Lookup', 'Whois Lookup', data=data)

    def GetASNFromWhoisOutput(self, output):
        asn = output[0].split("|", 1)[0] # ASN is the first value
        return asn.strip()               # remove extra characters

    def WhoisLookup_old(self, ip):
        start_time = time.time()
        obj = IPWhois(ip)
        result = obj.lookup()
        duration = time.time() - start_time
        asn = result['asn']
        data = {
            'ASN': asn,
            'Lookup_Time': duration
        }
        self._add_result('Whois Lookup', 'Whois Lookup', data=data)

    def stop(self):
        pass

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.DataIngesterServiceRunForm(initial=config),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def bind_runtime_form(analyst, config):
        data = {'LookupType': config['LookupType'][0]}
        return forms.DataIngesterServiceRunForm(data=data)