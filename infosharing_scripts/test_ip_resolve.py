import csv
import sys
import multiprocessing
import requests
import time

import numpy as np
from ipwhois import IPWhois, IPDefinedError, ASNRegistryError, HTTPLookupError
from ipwhois.net import Net
from ipwhois.asn import IPASN
from pprint import pprint

def __resolve_ip_addr(ip_addr):
	#net = Net("74.125.225.229")
	net = Net(ip_addr)
	obj = IPASN(net)
	result = obj.lookup()
	#object = IPWhois(ip_addr)
	#result = object.lookup_rdap(depth=1)
	# try:
	# 	get_url = 'https://rdap.db.ripe.net/autnum/' + str(result['asn'])
	# 	response = requests.get(url=get_url)
	# except Exception:
	# 	print "Failed!"
	# 	pass
	return obj.lookup()

def __sequential_resolve(ip_addrs):
	asns = []
	for ip_addr in ip_addrs:
		__resolve_ip_addr(ip_addr)

if __name__ == '__main__':
	with open(sys.argv[1]) as ip_file:
		ip_addrs = [x.strip() for x in ip_file]
	multiprocess_times = []
	print("Starting multiprocess loop")
	
	thread_times = []
	
	for i in range(2, 10):
		print("Calculating times for pool size " + str(i))
		p = multiprocessing.Pool(i)
		for j in range(10):
			start_time = time.time()
			p.map(__resolve_ip_addr, ip_addrs)
			end_time = time.time()
			multiprocess_times.append(end_time - start_time)
		thread_times.append((i, np.mean(multiprocess_times)))
	
	with open('multiprocessing_times.csv', 'w') as times_file:
		times_writer = csv.writer(times_file)
		header = ["pool_size", "mean_time"]
		times_writer.writerow(header)
		for thread_time in thread_times:
			row = [thread_time[0], thread_time[1]]
			times_writer.writerow(row)
	
	sequential_times = []
	print("Starting sequential loop")
	for j in range(10):
		start_time = time.time()
		__sequential_resolve(ip_addrs)
		end_time = time.time()
		sequential_times.append(end_time - start_time)
	mean = np.mean(sequential_times)
	print("Mean time for sequential: " + str(mean))
