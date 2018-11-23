# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Generate the Intrusion Prevention Deployment Report."""

import os
import re
import csv
from ds_utils import ds_utils

RESULT_PATH = "../results"

REPORT_NAME = "Intrusion Prevention Deployment Report"

NO_PROTECTION_STRING = "no_protection"
IPS_NOT_ENABLED_STRING = "ips_not_enabled"
IPS_RULES_NOT_APPLIED_STRING = "ips_rules_not_applied"

def generate_deployment_report(api_utils):
    """Generate the Intrusion Prevention Deployment Report."""

    # get the information of hosts
    hosts = api_utils.get_hosts()

    # loop all hosts to get deployment status
    unprotected_hosts = {NO_PROTECTION_STRING: [], IPS_NOT_ENABLED_STRING: [], IPS_RULES_NOT_APPLIED_STRING: []}
    progress_cnt = 0
    for host_id, host_info in hosts.items():
        if progress_cnt == len(hosts.items())-1:
            print("retrieving host data {0} / {1}".format(len(hosts.items()), len(hosts.items())))
        elif progress_cnt % 100 == 0:
            print("retrieving host data {0} / {1}".format(progress_cnt, len(hosts.items())))
        progress_cnt += 1
        
        status = api_utils.get_host_status(host_id)['overallStatus']
        re_no_agent = re.compile("No Agent")
        if re_no_agent.search(status):
            unprotected_hosts[NO_PROTECTION_STRING].append(host_info['name'])
            continue

        ips_status = api_utils.get_host_status(host_id)['overallDpiStatus']
        re_ips_off = re.compile("^Intrusion Prevention: Off,")
        re_ips_no_rule = re.compile(", no rules$")
        if re_ips_off.search(ips_status):
            unprotected_hosts[IPS_NOT_ENABLED_STRING].append(host_info['name'])
            continue
        elif re_ips_no_rule.search(ips_status):
            unprotected_hosts[IPS_RULES_NOT_APPLIED_STRING].append(host_info['name'])
            continue
        
    # write the report
    if not os.path.exists(RESULT_PATH):
        os.makedirs(RESULT_PATH)
    with open(os.path.join(RESULT_PATH, REPORT_NAME + ".csv"), 'w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow([REPORT_NAME])
        writer.writerow([])
        writer.writerow(["# This report evaluates the hosts that you have added to Deep Security Manager"])
        writer.writerow(["# and shows how many of them are protected by a Deep Security Agent or Deep Security Virtual Appliance,"])
        writer.writerow(["# how many of the protected hosts have intrusion prevention enabled,"])
        writer.writerow(["# and how many of those hosts have intrusion prevention rules assigned to them."])
        writer.writerow([])

        writer.writerow(["Hosts", "Total Number of Hosts"])
        if len(hosts) > 100:
            writer.writerow(['; '.join([host_info['name'] for host_id, host_info in hosts.items()][:100]) + ", ...", len(hosts)])
        else:
            writer.writerow(['; '.join([host_info['name'] for host_id, host_info in hosts.items()]), len(hosts)])
        writer.writerow([])

        if len(hosts) > 0:
            writer.writerow([
                "{0:.2f}% ({1}/{2}) of hosts don't have Deep Security installed".format(
                    len(unprotected_hosts[NO_PROTECTION_STRING]) / len(hosts) * 100,
                    len(unprotected_hosts[NO_PROTECTION_STRING]),
                    len(hosts)
                )
            ])
            writer.writerow(["Call to action [How to install Deep Security Agent: https://help.deepsecurity.trendmicro.com/Get-Started/Install/install-dsa.html]"])
            writer.writerow(["Call to action [How to install Deep Security Virtual Appliance: https://help.deepsecurity.trendmicro.com/11_0/on-premise/Get-Started/Install/ig-deploy-nsx.html]"])
            writer.writerow([])
        
        if len(hosts) - len(unprotected_hosts[NO_PROTECTION_STRING]) > 0:
            writer.writerow([
                "{0:.2f}% ({1}/{2}) of hosts that have Deep Security installed don't have Intrusion Prevention enabled".format(
                    len(unprotected_hosts[IPS_NOT_ENABLED_STRING]) / (len(hosts) - len(unprotected_hosts[NO_PROTECTION_STRING])) * 100,
                    len(unprotected_hosts[IPS_NOT_ENABLED_STRING]),
                    len(hosts) - len(unprotected_hosts[NO_PROTECTION_STRING])
                )
            ])
            writer.writerow(["Call to action [How to set up intrusion prevention: https://help.deepsecurity.trendmicro.com/set-up-intrusion-prevention.html]"])
            writer.writerow([])
            
        if len(hosts) - len(unprotected_hosts[NO_PROTECTION_STRING]) - len(unprotected_hosts[IPS_NOT_ENABLED_STRING]) > 0:
            writer.writerow([
                "{0:.2f}% ({1}/{2}) of hosts that have Intrusion Prevention enabled don't have rules assigned".format(
                    len(unprotected_hosts[IPS_RULES_NOT_APPLIED_STRING]) / (len(hosts) - len(unprotected_hosts[NO_PROTECTION_STRING]) - len(unprotected_hosts[IPS_NOT_ENABLED_STRING])) * 100,
                    len(unprotected_hosts[IPS_RULES_NOT_APPLIED_STRING]),
                    len(hosts) - len(unprotected_hosts[NO_PROTECTION_STRING]) - len(unprotected_hosts[IPS_NOT_ENABLED_STRING])
                )
            ])
            writer.writerow(["Call to action [How to run a recommendation scan: https://help.deepsecurity.trendmicro.com/Policies/ug-rec-scan.html]"])
            writer.writerow([])

        writer.writerow(["Hosts that don't have Deep Security installed"])
        if unprotected_hosts[NO_PROTECTION_STRING]:
            for no_protection_host in unprotected_hosts[NO_PROTECTION_STRING]:
                writer.writerow([no_protection_host])
        else:
            writer.writerow(["None"])
        writer.writerow([])

        writer.writerow(["Hosts that have Deep Security installed but don't have Intrusion Prevention enabled"])
        if unprotected_hosts[IPS_NOT_ENABLED_STRING]:
            for ips_not_enabled_host in unprotected_hosts[IPS_NOT_ENABLED_STRING]:
                writer.writerow([ips_not_enabled_host])
        else:
            writer.writerow(["None"])
        writer.writerow([])

        writer.writerow(["Hosts that have Intrusion Prevention enabled but no rules assigned"])
        if unprotected_hosts[IPS_RULES_NOT_APPLIED_STRING]:
            for ips_rules_not_applied_host in unprotected_hosts[IPS_RULES_NOT_APPLIED_STRING]:
                writer.writerow([ips_rules_not_applied_host])
        else:
            writer.writerow(["None"])
        writer.writerow([])

def main():
    """Main function"""

    # generate the report
    # use "with" statement to automatically end the session after API calls
    with ds_utils.APIUtils() as api_utils:
        generate_deployment_report(api_utils)

if __name__ == "__main__":
    main()
