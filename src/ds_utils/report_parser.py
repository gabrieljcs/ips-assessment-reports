# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Extract the data we need from the Qualys report."""

from lxml import etree

def get_parsed_report(report_path):
    """Parse the third-party report.

    Args:
        report_path: The path to the third-party report.

    Returns:
        The report that is parsed from the third-party report.
    """

    print("Parsing the report...")
    report = {}
    tree = etree.parse(report_path)
    root = tree.getroot()
    # loop all hosts by IP
    for host in root.findall('IP'):
        vul_infos = []

        categories = host.findall('./VULNS/CAT')
        for category in categories:
            vulns = category.findall('./VULN')
            for vuln in vulns:
                cve_ids = vuln.findall('./CVE_ID_LIST/CVE_ID/ID')
                for cve_id in cve_ids:
                    vul_infos.append(
                        {
                            'cve_id': cve_id.text,
                            'third_party': {
                                'title': vuln.find('./TITLE').text,
                                'qid': vuln.get('number'),
                                'category': category.get('value'),
                                'protocol': category.get('protocol'),
                                'port': category.get('port'),
                                'type': "VULN"
                            }
                        }
                    )

        # potential vulnerability
        categories = host.findall('./PRACTICES/CAT')
        for category in categories:
            practices = category.findall('./PRACTICE')
            for practice in practices:
                cve_ids = practice.findall('./CVE_ID_LIST/CVE_ID/ID')
                for cve_id in cve_ids:
                    vul_infos.append(
                        {
                            'cve_id': cve_id.text,
                            'third_party': {
                                'title': practice.find('./TITLE').text,
                                'qid': practice.get('number'),
                                'category': category.get('value'),
                                'protocol': category.get('protocol'),
                                'port': category.get('port'),
                                'type': "PRACTICE"
                            }
                        }
                    )

        report[host.get('value')] = {'vul_infos': vul_infos}

    return report
