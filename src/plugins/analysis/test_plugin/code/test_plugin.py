from ipaddress import ip_address

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
		result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)
		for key in ['uris', 'ips_v4', 'ips_v6']:
		    result[key] = self._remove_duplicates(result[key])
		file_object.processed_analysis[self.NAME] = self._get_augmented_result(result)
		return file_object
		
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


