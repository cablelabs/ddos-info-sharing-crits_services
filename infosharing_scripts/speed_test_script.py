from datetime import datetime
import requests
from ipwhois import IPWhois, IPDefinedError, ASNRegistryError, HTTPLookupError
from ipwhois.net import Net
from ipwhois.asn import IPASN

start = datetime.now()
ip_address = '150.101.140.216' # ''8.8.8.8'
object = IPWhois(ip_address)
try:
    result = object.lookup_rdap(depth=1)
except ValueError:
    raise
except IPDefinedError:
    raise ValueError("IP address " + ip_address + " is reserved for some special purpose.")
except ASNRegistryError:
    raise ValueError("IP address " + ip_address + " does not have entry in ASN registry.")
except HTTPLookupError as e:
    raise Exception(e.message)

#number = get_as_number_from_ipwhois("8.8.8.8")
#print number
#name = get_as_name_from_rdap("8.8.8.8")
end = datetime.now()
#print name
print result['asn']
print end - start


get_url = 'https://rdap.db.ripe.net/autnum/' + str(result['asn'])
start2 = datetime.now()
response = requests.get(url=get_url)
end2 = datetime.now()
response_json = response.json()
print response_json['name']
print end2 - start2


start3 = datetime.now()
net = Net(ip_address)
obj = IPASN(net)
end3 = datetime.now()
print obj.lookup()
print end3 - start3


