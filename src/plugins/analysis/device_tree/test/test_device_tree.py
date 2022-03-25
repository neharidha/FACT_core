from pathlib import Path

import pytest

from objects.file import FileObject

from ..code.device_tree import AnalysisPlugin

TEST_DATA = Path(__file__).parent.parent / 'test/data'
TEST_FILE = TEST_DATA / 'device_tree.dtb'
EXPECTED_RESULT = 'model = "Manufac XYZ1234ABC";'


@pytest.mark.AnalysisPluginClass(lambda: AnalysisPlugin)
def test_process_object(analysis_plugin):
    test_object = FileObject()
    test_object.processed_analysis['file_type'] = {'mime': 'linux/device-tree'}
    test_object.file_path = str(TEST_FILE)
    result = analysis_plugin.process_object(test_object)

    assert result.processed_analysis[analysis_plugin.NAME]['summary'] == ['device tree found']


def test_convert_device_tree():
    result = AnalysisPlugin.convert_device_tree(TEST_FILE)

    assert EXPECTED_RESULT in result


def test_dump_device_tree():
    test_file = TEST_DATA / 'binary_file_containing_device_tree'
    result = AnalysisPlugin.dump_device_tree(test_file)

    assert EXPECTED_RESULT in result
