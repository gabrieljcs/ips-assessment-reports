# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Download the information of CVEs from NVD."""

import os
import re
import requests

NVD_PATH = "../nvd"

def download_nvd():
    """Download the NVD and save to the nvd folder."""

    if not os.path.exists(NVD_PATH):
        os.makedirs(NVD_PATH)

    # get the download links from the https://nvd.nist.gov
    data_feeds = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    filenames = re.findall(r"nvdcve-1.0-[0-9]*.json.zip", data_feeds.text)

    if not filenames:
        print("Fail to download the NVD")
        return

    print("Download list of CVEs from https://nvd.nist.gov/")
    for filename in filenames:
        print("Downloading " + filename + "...")
        cve = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
        with open(os.path.join(NVD_PATH, filename), 'wb') as file:
            for chunk in cve:
                file.write(chunk)
