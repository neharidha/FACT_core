def kconfig_contains(kconfig: str, options):
    for line in kconfig.splitlines():
        if line[-2:] != '=y':
            continue

        if str.strip(line)[len('CONFIG_'):-len('=y')] in options:
            return True

    return False


def construct_result(file_object):
    # Avoid circular import
    from plugins.analysis.architecture_detection.internal.kconfig.arm import construct_result as construct_result_arm
    from plugins.analysis.architecture_detection.internal.kconfig.mips import construct_result as construct_result_mips
    result = {}
    kconfig_str = file_object.processed_analysis.get('kernel_config', {}).get('kernel_config')

    if kconfig_str is None:
        return {}

    result.update(construct_result_arm(kconfig_str))
    result.update(construct_result_mips(kconfig_str))

    return result
