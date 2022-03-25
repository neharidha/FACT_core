import json
import os

import pytest
from common_helper_files import get_dir_of_file

from objects.file import FileObject
from plugins.analysis.known_vulnerabilities.code.known_vulnerabilities import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


@pytest.mark.AnalysisPluginClass(lambda: AnalysisPlugin)
class TestAnalysisPluginsKnownVulnerabilities:
    with open(os.path.join(TEST_DATA_DIR, 'sc.json'), 'r') as json_file:
        _software_components_result = json.load(json_file)

    def test_process_object_yara(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'testfile'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '1234'}
        test_file.processed_analysis['software_components'] = {}

        results = analysis_plugin.process_object(test_file).processed_analysis[analysis_plugin.NAME]

        assert len(results) == 4, 'incorrect number of vulnerabilities found (summary + tag + one result)'
        assert 'DLink_Bug' in results, 'test match not found'
        assert results['DLink_Bug']['score'] == 'high', 'incorrect or no score found in meta data'

        assert 'DLink_Bug' in results['tags']
        assert results['tags']['DLink_Bug']['propagate']

    def test_process_object_software(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '1234'}
        test_file.processed_analysis['software_components'] = self._software_components_result

        results = analysis_plugin.process_object(test_file).processed_analysis[analysis_plugin.NAME]

        assert len(results) == 3, 'incorrect number of vulnerabilities found (summary + tag + one result)'
        assert 'Heartbleed' in results, 'test match not found'
        assert results['Heartbleed']['score'] == 'high', 'incorrect or no score found in meta data'

    def test_process_object_software_wrong_version(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '1234'}
        self._software_components_result['OpenSSL']['meta']['version'] = ['0.9.8', '1.0.0', '']
        test_file.processed_analysis['software_components'] = self._software_components_result

        results = analysis_plugin.process_object(test_file).processed_analysis[analysis_plugin.NAME]

        assert ['summary'] == list(results.keys()), 'no match should be found'

    def test_process_object_hash(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'empty'))
        test_file.processed_analysis['file_hashes'] = {'sha256': '7579d10e812905e134cf91ad8eef7b08f87f6f8c8e004ebefa441781fea0ec4a'}
        test_file.processed_analysis['software_components'] = {}

        results = analysis_plugin.process_object(test_file).processed_analysis[analysis_plugin.NAME]

        assert len(results) == 3, 'incorrect number of vulnerabilities found (summary + tag + one result)'
        assert 'Netgear_CGI' in results, 'test match not found'
        assert results['Netgear_CGI']['score'] == 'medium', 'incorrect or no score found in meta data'

        assert 'Netgear_CGI' in results['tags']
        assert not results['tags']['Netgear_CGI']['propagate']
