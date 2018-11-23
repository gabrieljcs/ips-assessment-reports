# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Conver intrusion prevention deployment report to xlsx format"""

import csv
import re
import xlsxwriter

def parse(csv_file, xlsx_file):
    """
    parse csv file contain deployment report
    convert content into xlsx file with chart
     Args:
        csv_file (str): which csv file to parse, include file path and file name
        xlsx_file (str): where xlsx would create, include file path and file name

    """

    #Summary info
    no_dsa_pattern = r'\((\d+)/(\d+)\).*don\'t have Deep Security installed'
    disable_ips_pattern = r'\((\d+)/(\d+)\).*don\'t have Intrusion Prevention enabled'
    no_rule_pattern = r'\((\d+)/(\d+)\).*don\'t have rules assigned'
    summary_patterns = re.compile('{}|{}|{}'.format(no_dsa_pattern, disable_ips_pattern, no_rule_pattern))
    no_dsa_count = None
    no_ips_count = None
    no_rule_count = None
    description = []
    summary = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]

    #Detail info
    no_dsa_list_title = r"Hosts that don't have Deep Security installed"
    disable_ips_list_title = r"Hosts that have Deep Security installed but don't have Intrusion Prevention enabled"
    no_rule_list_title = r"Hosts that have Intrusion Prevention enabled but no rules assigned"
    title_patterns = re.compile('({})|({})|({})'.format(no_dsa_list_title, disable_ips_list_title, no_rule_list_title))
    no_dsa_list = []
    no_ips_list = []
    no_rule_list = []
    host_list = [
        no_dsa_list,
        no_ips_list,
        no_rule_list
    ]

    #Help url
    action_pattern = re.compile('\[(.+)\: (.+)\]')
    action_list = []


    #Parse csv file
    with open(csv_file, 'r', newline='') as csv_file:
        rows = csv.reader(csv_file, quotechar='"', delimiter=',', skipinitialspace=True)
        for index, row in enumerate(rows):
            if not row:
                continue

            if row[0].startswith('#'):
                description.append(row[0].replace('# ', ''))
                continue

            search = summary_patterns.search(row[0])
            if search:
                current_pattern = next((i for i, x in enumerate(search.groups()) if x), None)
                summary[int(current_pattern/2)] = ( int(search.group(current_pattern+1)), int(search.group(current_pattern+2)) - int(search.group(current_pattern+1)) )
                continue

            search = action_pattern.search(row[0])
            if search:
                action_list.append((search.group(1), search.group(2)))
                if len(action_list) == 4:
                    break

        current_pattern = -1
        for index, row in enumerate(rows):
            if not row or re.match('None', row[0]):
                continue

            search = title_patterns.search(row[0])
            if search:
                current_pattern = next((i for i, x in enumerate(search.groups()) if x), None)
                continue

            if current_pattern == -1:
                continue
            host_list[current_pattern].append(row[0])

    no_dsa_count, no_ips_count, no_rule_count = summary

    #Write xlsx file
    workbook = xlsxwriter.Workbook(xlsx_file)
    summary_worksheet = workbook.add_worksheet('Summary')
    rawdata_worksheet = workbook.add_worksheet('Data')
    no_dsa_worksheet = workbook.add_worksheet("Hosts that don't have DS")
    no_ips_worksheet = workbook.add_worksheet("Hosts that don't have IPS")
    no_rule_worksheet = workbook.add_worksheet("Hosts that don't have rules")

    #Rawdata worksheet
    data = [
        ['', 'Deep Security installed', 'Intrusion Prevention enabled', 'rules assigned'],
        ['Yes', no_dsa_count[1], no_ips_count[1], no_rule_count[1]],
        ['No', no_dsa_count[0], no_ips_count[0], no_rule_count[0]]
    ]
    rawdata_worksheet.write_column('A1', data[0], workbook.add_format({'bold': True}))
    rawdata_worksheet.write_column('B1', data[1])
    rawdata_worksheet.write_column('C1', data[2])

    #No DSA install worksheet
    no_dsa_worksheet.write_row(0, 0, [no_dsa_list_title])
    no_dsa_worksheet.write_column(1, 0, no_dsa_list)

    #No IPS enable worksheet
    no_ips_worksheet.write_row(0, 0, [disable_ips_list_title])
    no_ips_worksheet.write_column(1, 0, no_ips_list)

    #No Rule worksheet
    no_rule_worksheet.write_row(0, 0, [no_rule_list_title])
    no_rule_worksheet.write_column(1, 0, no_rule_list)

    #Summary worksheet
    chart = workbook.add_chart({'type': 'column', 'subtype': 'percent_stacked'})
    chart.add_series({
        'name': '=Data!$B$1',
        'categories': '=Data!$A$2:$A$4',
        'values':     '=Data!$B$2:$B$4',
        'fill':   {'color': '#21BC3B'}
    })
    chart.add_series({
        'name': '=Data!$C$1',
        'categories': '=Data!$A$2:$A$4',
        'values':     '=Data!$C$2:$C$4',
        'fill':   {'color': '#C22828'}
    })
    chart.set_title ({'name': 'Protected hosts'})
    chart.set_x_axis({
        'name': 'Status',
    })

    chart.set_y_axis({
        'major_unit' : 0.2,
        'min' : 0,
        'max' : 1
    })

    summary_worksheet.insert_chart('A1', chart)
    summary_worksheet.write_column('A16', description)
    for index, (text, url) in enumerate(action_list):
        summary_worksheet.write_url('A'+str(index+20), url, string = text)
    summary_worksheet.activate()

    workbook.close()