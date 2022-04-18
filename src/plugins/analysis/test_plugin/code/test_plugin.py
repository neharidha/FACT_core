from ipaddress import ip_address
from dns import resolver
import whois
import time, pprint, datetime
from ipwhois.net import Net
from ipwhois.asn import IPASN

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


class AnalysisPlugin(AnalysisBasePlugin):
	NAME = 'test_plugin'
	DEPENDENCIES = ['ip_and_uri_finder']
	DESCRIPTION = (
	'Test Plugin'
	)
	VERSION = '0.1'

	def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
		self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
		super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

	def process_object(self, file_object):
		final_data = {} #dict of original artifact mapped to analysis
		result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		for key in ['uris', 'ips_v4', 'ips_v6']:
		    result[key] = self._remove_duplicates(result[key])
		for key, data_list in result.items():
			if key not in ['uris', 'ips_v4', 'ips_v6']:
				continue
			for data in data_list:
				print(f'$ {data} - {type(data)}')
				if type(data) == list:
					print(f'##DATA LIST: {data}')
					data = data[0]
				if key == 'uris':
					data = self.get_domains_from_uri(data)
					final_data[data] = {}
					final_data[data]['dns'] = self.get_ips_from_domain(data)
					final_data[data]['whois'] = self.get_domain_whois(data)
				elif key == 'ips_v4':
					final_data[data] = {}
					final_data[data]['dns'] = self.get_domains_from_ip(data)
					final_data[data]['whois'] = self.get_ip_whois(data)
		print(f'##################\n\n{final_data}\n\n################')
		file_object.processed_analysis[self.NAME] = final_data #self._get_augmented_result(result)
		return file_object
		
	def get_domains_from_uri(self, uri):
		sub_strs = uri.split("://")
		if len(sub_strs) == 1: #case where no protocol
			domain = (sub_strs[0])
		else:
			domain = (sub_strs[1].split("/")[0])
		return domain
		

	def get_ips_from_domain(self, domain):

		ips = []
		print(f'requesting {domain}')
		response = resolver.resolve(domain,'A')
		for ip in response:
			ips.append(str(ip))
		return ips
				
	def get_domains_from_ip(self, ip):
		domains = []
		print(f'requesting {ip}')
		response = resolver.resolve_address(ip)
		for domain in response:
			domains.append(str(domain))

		return domains
	
	def get_ip_whois(self, ip):
		return pprint.pformat(IPASN(Net(ip)).lookup())
		
	def get_domain_whois(self, domain):
		data_dict = whois.query(domain).__dict__
		for key, value in data_dict.items():
			if type(value) == set:
				data_dict[key] = list(data_dict[key])
			elif type(value) == datetime.datetime:
				data_dict[key] = value.strftime("%m-%d-%y %H:%M")
		if 'statuses' in data_dict:
			data_dict.pop('statuses')
		return pprint.pformat(data_dict)
		
		
	def _get_augmented_result(self, result):
		result['summary'] = self._get_summary(result)
		result['system_version'] = self.ip_and_uri_finder.system_version
		return result
	
	@staticmethod
	def _remove_duplicates(input_list):
		return list(set(input_list))
	
	@staticmethod
	def _get_summary(results):
		summary = []
		for key in ['uris']:
			summary.extend(results[key])
		for key in ['ips_v4', 'ips_v6']:
			for i in results[key]:
				summary.append(i[0])
		return summary






