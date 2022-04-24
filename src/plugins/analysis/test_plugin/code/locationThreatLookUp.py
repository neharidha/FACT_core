from ipdata import ipdata
import socket

ipd=ipdata.IPData('94e7d24a7610566ca951ae281d974d19d7be21764420af641f2f6d0a')

input = ['8.8.8.8','www.facebook.com']
locators = ['country_name', 'threat']
ipMapping = {}
ips = []
dict = {}
for str in input:
	if (str[0:3] == 'www'):
		ipMapping[str] = socket.gethostbyname(str)
		ips.append(ipMapping[str])
	else:
		ips.append(str)

for ip in ips:
	response = ipd.lookup(ip)
	dict[ip] = {}
	for locator in locators:
		dict[ip][locator] = response[locator]

for key in dict.keys():
	print(key, dict[key])
