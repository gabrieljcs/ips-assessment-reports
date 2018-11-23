# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Generate the Intrusion Prevention Recommendation Scan Report."""

import os
import csv
from ds_utils import ds_utils

TMP_PATH = "../tmp"
NVD_PATH = "../nvd"
RESULT_PATH = "../results"

REPORT_NAME = "Intrusion Prevention Recommendation Scan Report"

PROTECTED_STRING = "protected"
UNPROTECTED_STRING = "unprotected"

def generate_reco_scan_report(api_utils, cve_utils):
    """Generate the Intrusion Prevention Recommendation Scan Report."""

    # get the information of hosts
    hosts = api_utils.get_hosts()

    # get the host groups for classification
    host_groups = api_utils.get_host_groups()
    host_groups[None] = {'name': "Computers"}

    # get the information of Intrusion Prevention Rules
    ips_rules = ds_utils.CacheUtils.get_ips_rules(api_utils, TMP_PATH)
    need_ips_rule_update = False

    # create a dictionary to store the mapping of CVEs and Intrusion Prevention Rule IDs
    cve_to_rule_id = cve_utils.get_cve_to_rule_id(ips_rules)

    # create a dictionary to store the mapping of CVEs and Intrusion Prevention Rule names
    cve_to_rule_name = cve_utils.get_cve_to_rule_name(ips_rules)

    # import the NVD
    nvd = ds_utils.CacheUtils.get_nvd(NVD_PATH, TMP_PATH)
    need_nvd_update = False

    # loop all hosts to get protection status
    vuls_reported_by_ds = {PROTECTED_STRING: [], UNPROTECTED_STRING: []}
    recommended_rules = {'assigned': [], 'recommended_to_assign': [], 'recommended_to_unassign': []}
    progress_cnt = 0
    for host_id, host_info in hosts.items():
        if progress_cnt == len(hosts.items())-1:
            print("retrieving host data {0} / {1}".format(len(hosts.items()), len(hosts.items())))
        elif progress_cnt % 100 == 0:
            print("retrieving host data {0} / {1}".format(progress_cnt, len(hosts.items())))
        progress_cnt += 1
        
        # get all the recommended rule IDs
        reco_rule_ids = api_utils.get_reco_rule_ids_on_host(host_id)
        reco_rule_id_set = set(reco_rule_ids)

        # get all the assigned rule IDs
        assigned_rule_ids = api_utils.get_assigned_rule_ids_on_host(host_id)
        assigned_rule_id_set = set(assigned_rule_ids)

        host_name = host_info['name']
        host_group_name = host_groups[host_info['hostGroupID']]['name']

        for rule_id in assigned_rule_id_set:
            recommended_rules['assigned'].append({
                'rule_id': rule_id,
                'host_name': host_name,
                'host_group_name': host_group_name
            })

        for rule_id in reco_rule_id_set - assigned_rule_id_set:
            recommended_rules['recommended_to_assign'].append({
                'rule_id': rule_id,
                'host_name': host_name,
                'host_group_name': host_group_name
            })

        for rule_id in assigned_rule_id_set - reco_rule_id_set:
            recommended_rules['recommended_to_unassign'].append({
                'rule_id': rule_id,
                'host_name': host_name,
                'host_group_name': host_group_name
            })

        # Deep Security Recommendation Scan return a list of Intrusion Prevention Rules,
        # A CVE may need multiple rules to protect.
        # On the other hand, a rule may be created for multiple CVEs.
        # We have to make sure that a CVE is actually vulnerable on the host,
        # i.e., all the rules corresponding to a CVE are remommended/assigned.

        # get all the CVEs reported by Deep Security Recommendation Scan
        vuls_reported_by_ds_on_host = []
        for reco_rule_id in reco_rule_id_set:
            if str(reco_rule_id) not in ips_rules:
                need_ips_rule_update = True
                continue
            for cve in ips_rules[str(reco_rule_id)]['cves']:
                vulnerable = True
                for rule_id in cve_to_rule_id[cve]:
                    if rule_id not in reco_rule_id_set:
                        vulnerable = False
                if vulnerable:
                    vuls_reported_by_ds_on_host.append(cve)
        vuls_reported_by_ds_on_host = set(vuls_reported_by_ds_on_host)

        # get all the CVEs protected by Deep Security Intrusion Prevention Rules
        protected_cves_on_host = []
        for assigned_rule_id in assigned_rule_id_set:
            if str(assigned_rule_id) not in ips_rules:
                need_ips_rule_update = True
                continue
            for cve_id in ips_rules[str(assigned_rule_id)]['cves']:
                vulnerable = True
                for rule_id in cve_to_rule_id[cve_id]:
                    if rule_id not in reco_rule_id_set or rule_id not in assigned_rule_id_set:
                        vulnerable = False
                if vulnerable:
                    protected_cves_on_host.append(cve_id)

        protected_cves_on_host = set(protected_cves_on_host)
        for cve_id in protected_cves_on_host:
            vuls_reported_by_ds[PROTECTED_STRING].append({
                'host_name': host_info['name'],
                'host_group_name': host_groups[host_info['hostGroupID']]['name'],
                'cve_id': cve_id
            })

        # get all the unprotected CVEs
        unprotected_cves_on_host = vuls_reported_by_ds_on_host - protected_cves_on_host
        for cve_id in unprotected_cves_on_host:
            vuls_reported_by_ds[UNPROTECTED_STRING].append({
                'host_name': host_info['name'],
                'host_group_name': host_groups[host_info['hostGroupID']]['name'],
                'cve_id': cve_id
            })

    severity_dict = {
        ds_utils.CVE_SEVERITY_CRITICAL: 0,
        ds_utils.CVE_SEVERITY_HIGH: 0,
        ds_utils.CVE_SEVERITY_MEDIUM: 0,
        ds_utils.CVE_SEVERITY_LOW: 0,
        ds_utils.CVE_SEVERITY_NONE: 0,
        ds_utils.CVE_SEVERITY_UNKOWN: 0
    }
    cnt = {PROTECTED_STRING: severity_dict.copy(), UNPROTECTED_STRING: severity_dict.copy()}
    for cve in vuls_reported_by_ds[PROTECTED_STRING]:
        cve_id = cve['cve_id']
        if cve_id not in nvd:
            need_nvd_update = True
            continue

        cnt[PROTECTED_STRING][nvd[cve_id]['severity']] += 1

    for cve in vuls_reported_by_ds[UNPROTECTED_STRING]:
        cve_id = cve['cve_id']
        if cve_id not in nvd:
            need_nvd_update = True
            continue

        cnt[UNPROTECTED_STRING][nvd[cve_id]['severity']] += 1

    # write the report
    if not os.path.exists(RESULT_PATH):
        os.makedirs(RESULT_PATH)
    with open(os.path.join(RESULT_PATH, REPORT_NAME + ".csv"), 'w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow([REPORT_NAME])
        writer.writerow([])
        writer.writerow(["# This report shows information based on your most recent recommendation scans."])
        writer.writerow(["# It displays the unprotected CVEs on your hosts that you can protect against by assigning additional rules."])
        writer.writerow(["# It also lists the number of CVEs that the currently assigned rules are protecting against,"])
        writer.writerow(["# and the number of rules recommended for assignment and unassignment."])
        writer.writerow([])

        writer.writerow(["Hosts", "Total Number of Hosts"])
        if len(hosts) > 100:
            writer.writerow(['; '.join([host_info['name'] for host_id, host_info in hosts.items()][:100]) + ", ...", len(hosts)])
        else:
            writer.writerow(['; '.join([host_info['name'] for host_id, host_info in hosts.items()]), len(hosts)])
        writer.writerow([])

        writer.writerow(["CVEs already protected (Based on severity level)"])

        for severity, _ in severity_dict.items():
            if cnt[PROTECTED_STRING][severity] + cnt[UNPROTECTED_STRING][severity] > 0:
                writer.writerow([
                    "{0}: {1:.2f}% ({2}/{3})".format(
                        severity,
                        cnt[PROTECTED_STRING][severity]/(cnt[PROTECTED_STRING][severity]+cnt[UNPROTECTED_STRING][severity])*100,
                        cnt[PROTECTED_STRING][severity],
                        cnt[PROTECTED_STRING][severity]+cnt[UNPROTECTED_STRING][severity]
                    )
                ])

        writer.writerow([])

        writer.writerow([
            "Number of Recommendations",
            "Total Number of Recommendations",
            "Number of Rules Recommended for Assignment",
            "Number of Rules Recommended for Unassignment"
        ])
        writer.writerow([
            "Intrusion Prevention Rules Recommended",
            len(recommended_rules['assigned'])+len(recommended_rules['recommended_to_assign'])-len(recommended_rules['recommended_to_unassign']),
            len(recommended_rules['recommended_to_assign']),
            len(recommended_rules['recommended_to_unassign'])
        ])
        writer.writerow([])

        writer.writerow(["Call to action [How to assign rules: https://help.deepsecurity.trendmicro.com/Protection-Modules/Intrusion-Prevention/ui-policies-rules-ip.html#Assignin]"])
        writer.writerow([])

        writer.writerow(["Unprotected CVEs on hosts:"])
        writer.writerow([
            "CVE ID",
            "Host",
            "Host Group",
            "CVSS version",
            "Severity",
            "CVSS Base Score",
            "Vector String",
            "Rule Name"
        ])
        for vul in vuls_reported_by_ds[UNPROTECTED_STRING]:
            cve_id = vul['cve_id']
            if cve_id not in nvd:
                need_nvd_update = True
                continue

            writer.writerow([
                cve_id,
                vul['host_name'],
                vul['host_group_name'],
                nvd[cve_id]['cvssVersion'],
                nvd[cve_id]['severity'],
                nvd[cve_id]['baseScore'],
                nvd[cve_id]['vectorString'],
                ', '.join(cve_to_rule_name[cve_id])
            ])
        writer.writerow([])

        header = [
            "Rule Name",
            "Host",
            "Host Group",
            "CVEs"
        ]
        writer.writerow(["Rules Recommended for Assignment"])
        writer.writerow(header)
        for item in recommended_rules['recommended_to_assign']:
            writer.writerow([
                ips_rules[str(item['rule_id'])]['identifier'] + '-' + ips_rules[str(item['rule_id'])]['name'],
                item['host_name'],
                item['host_group_name'],
                ', '.join(ips_rules[str(item['rule_id'])]['cves'])
            ])
        writer.writerow([])

        writer.writerow(["Rules Recommended for Unassignment"])
        writer.writerow(header)
        for item in recommended_rules['recommended_to_unassign']:
            writer.writerow([
                ips_rules[str(item['rule_id'])]['identifier'] + '-' + ips_rules[str(item['rule_id'])]['name'],
                item['host_name'],
                item['host_group_name'],
                ', '.join(ips_rules[str(item['rule_id'])]['cves'])
            ])

        if need_ips_rule_update:
            print("Please update the ips_rules.json or delete it and run this scipt again.")

        if need_nvd_update:
            print("Please update the NVD")

def main():
    """Main function"""

    # generate the report
    # use "with" statement to automatically end the session after API calls
    with ds_utils.APIUtils() as api_utils:
        cve_utils = ds_utils.CVEUtils()
        generate_reco_scan_report(api_utils, cve_utils)

if __name__ == "__main__":
    main()
