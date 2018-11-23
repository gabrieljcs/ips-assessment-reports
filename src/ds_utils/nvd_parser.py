# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Extract the data we need from the NVD data feeds."""

import os
import zipfile
import json
from .nvd_downloader import download_nvd

def get_parsed_nvd(nvd_path):
    """Parse the NVD.

    Args:
        nvd_path: The path to the NVD data feeds.

    Returns:
        The data that is parsed from the NVD data feeds.
    """

    # download the NVD
    download_nvd()

    result = {}
    # parse all zip files in nvd folder
    for file in os.listdir(nvd_path):
        if not os.path.isfile(os.path.join(nvd_path, file)):
            continue

        cves = {}
        with zipfile.ZipFile(os.path.join(nvd_path, file), 'r') as zip_file:
            with zip_file.open(zip_file.namelist()[0]) as json_file:
                cves = json.loads(json_file.read())

        # get the CVSS details
        for cve in cves['CVE_Items']:
            data = {}
            if 'baseMetricV3' in cve['impact']:
                data = {
                    'cvssVersion': 3,
                    'baseScore': cve['impact']['baseMetricV3']['cvssV3']['baseScore'],
                    'vectorString': cve['impact']['baseMetricV3']['cvssV3']['vectorString'].replace("CVSS:3.0/", ""),
                    'exploitabilityScore': cve['impact']['baseMetricV3']['exploitabilityScore'],
                    'impactScore': cve['impact']['baseMetricV3']['impactScore'],
                    'severity': cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'][0] + cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'][1:].lower()
                }
            elif 'baseMetricV2' in cve['impact']:
                data = {
                    'cvssVersion': 2,
                    'baseScore': cve['impact']['baseMetricV2']['cvssV2']['baseScore'],
                    'vectorString': cve['impact']['baseMetricV2']['cvssV2']['vectorString'].replace("(", "").replace(")", ""),
                    'exploitabilityScore': cve['impact']['baseMetricV2']['exploitabilityScore'],
                    'impactScore': cve['impact']['baseMetricV2']['impactScore'],
                    'severity': cve['impact']['baseMetricV2']['severity'][0] + cve['impact']['baseMetricV2']['severity'][1:].lower()
                }
            else:
                data = {
                    'cvssVersion': "Unknown",
                    'baseScore': "Unknown",
                    'vectorString': "Unknown",
                    'exploitabilityScore': "Unknown",
                    'impactScore': "Unknown",
                    'severity': "Unknown"
                }

            result[cve['cve']['CVE_data_meta']['ID']] = data

    return result
