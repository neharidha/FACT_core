import shlex
import subprocess
from subprocess import DEVNULL, PIPE
from typing import Union

import yaml


def _get_compatible_entry(dts: str) -> Union[str, None]:
    """
    Returns the node name of /cpus/cpu*/compatible and its value from a device tree.
    May return None because the spec does not guarantee the existence of this node.

    See the DeviceTree spec for more information https://www.devicetree.org/specifications/
    """

    dtc_process = subprocess.run(
        shlex.split('dtc -I dts -O yaml'),
        input=dts,
        stdout=PIPE,
        stderr=DEVNULL,
        universal_newlines=True,
        check=True,
    )

    # TODO Why do we need this?
    dt = dtc_process.stdout.replace('!u8', '')

    dt_yaml = yaml.load(dt)

    compatible = None
    dt_path = None

    for x in dt_yaml:
        if 'cpus' not in x:
            continue

        cpus = x['cpus']

        cpu_name = None
        # According to the naming convention such a key should always exist
        for key in cpus.keys():
            if 'cpu@' in key:
                cpu_name = key
                break

        cpu = cpus[cpu_name]
        if 'compatible' not in cpu.keys():
            continue

        compatible = cpu['compatible']
        dt_path = f'/cpus/{cpu_name}/compatible'
        break

    return f'{dt_path}: {compatible[0]}'


def construct_result(file_object):
    result = {}
    for dt_dict in file_object.processed_analysis.get('device_tree', {}).get('device_trees', []):
        dt = dt_dict['device_tree']
        result.update(
            {
                _get_compatible_entry(dt): 'DeviceTree',
            },
        )

    return result
