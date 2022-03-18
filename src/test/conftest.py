import pytest

import os
from typing import List, Optional
from helperFunctions.fileSystem import get_src_dir

from objects.file import FileObject
from objects.firmware import Firmware


# TODO replace
def get_test_data_dir():
    '''
    Returns the absolute path of the test data directory
    '''
    return os.path.join(get_src_dir(), 'test/data')


# TODO scope
@pytest.fixture
def firmware_object_factory():
    def factory_method(
            # Arguments to the FileObject constructor
            binary: Optional[bytes] = None,
            file_name: Optional[str] = None,
            file_path: Optional[str] = None,  # TODO must be subpath of test dir assert
            scheduled_analysis: List[str] = None,
            # Attributes of Firmware
            device_class = None,
            device_name = None,
            vendor = None,
            release_date = '1970-01-01',
            version = "0.1",  # TODO Why 0.1
            # Other
            processed_analysis = {},
    ):
        fw = Firmware(
            binary=binary,
            file_name=file_name,
            file_path=file_path,
            scheduled_analysis=scheduled_analysis,
        )

        fw.device_class = device_class
        fw.device_name = device_name
        fw.vendor = vendor
        fw.release_date = release_date
        fw.version = version

        processed_analysis = {
            'dummy': {'summary': ['sum a', 'fw exclusive sum a'], 'content': 'abcd', 'plugin_version': '0', 'analysis_date': 0.0},
            'unpacker': {'plugin_used': 'used_unpack_plugin', 'plugin_version': '1.0', 'analysis_date': 0.0},
            'file_type': {'mime': 'test_type', 'full': 'Not a PE file', 'summary': ['a summary'], 'plugin_version': '1.0', 'analysis_date': 0.0}
        }

        fw.processed_analysis.update(processed_analysis)

        if all_files_included_set:
            fw.list_of_all_included_files = list(fw.files_included)
            fw.list_of_all_included_files.append(fw.uid)
        return fw
    pass


@pytest.fixture
def simple_firmware(firmware_object_factory) -> Firmware:
    """ A simple firmware that can be used for most tests.
    For a more sophisticated approach see `firmware_factory`.
    """


@pytest.fixture
def file_object_factory():
    pass


@pytest.fixture
def simple_file(file_object_factory) -> FileObject:
    """ A simple file that can be used for most tests.
    For a more sophisticated approach see `firmware_factory`.
    """
