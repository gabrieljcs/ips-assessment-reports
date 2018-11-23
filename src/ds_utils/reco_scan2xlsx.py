# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Conver intrusion prevention risk report to xlsx format"""

import csv
import re
import xlsxwriter

def parse(csv_file, xlsx_file):
    """
    parse csv file contain intrusion prevention risk report
    convert content into xlsx file with chart
     Args:
        csv_file (str): which csv file to parse, include file path and file name
        xlsx_file (str): where xlsx would create, include file path and file name

    """
    #Summary info
    description = []

    #Severity info
    severity_pattern = re.compile(r'(.+):.+\((\d+)/(\d+)\)')
    severity_count = {}

    #Protected info
    unprotected_cve_list_title = r'Unprotected CVEs on hosts:'
    recommended2assign_list_title = r'Rules Recommended for Assignment'
    recommended2unassign_list_title = r'Rules Recommended for Unassignment'
    title_patterns = re.compile('({})|({})|({})'.format(unprotected_cve_list_title, recommended2assign_list_title, recommended2unassign_list_title))
    unprotected_list = []
    recommended2assign_list = []
    recommended2unassign_list = []
    host_list = [
        unprotected_list,
        recommended2assign_list,
        recommended2unassign_list
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

            search = severity_pattern.search(row[0])
            if search:
                severity_count[search.group(1)] = [int(search.group(2)), int(search.group(3)) - int(search.group(2))]

            search = action_pattern.search(row[0])
            if search:
                action_list.append((search.group(1), search.group(2)))
                break


        current_pattern = -1
        for index, row in enumerate(rows):
            if not row or re.match('None', row[0]):
                continue
            serach = title_patterns.search(row[0])
            if serach:
                current_pattern = next((i for i, x in enumerate(serach.groups()) if x), None)
                continue

            if current_pattern == -1:
                continue
            host_list[current_pattern].append(row)

    workbook = xlsxwriter.Workbook(xlsx_file)
    summary_worksheet = workbook.add_worksheet('Summary')
    rawdata_worksheet = workbook.add_worksheet('Data')
    unprotected_list_worksheet = workbook.add_worksheet('Unprotected CVEs')
    rule2assign_worksheet = workbook.add_worksheet('Rules Recom. for Assignment')
    rule2unassign_worksheet = workbook.add_worksheet('Rules Recom. for Unassignment')

    #Rawdata worksheet
    data = [['Severity level'], ['Protected'], ['Unprotected']]
    for key,values in severity_count.items():
        data[0].append(key)
        for i in range(len(values)):
            data[i+1].append(values[i])
    rawdata_worksheet.write_column('A1', data[0], workbook.add_format({'bold': True}))
    rawdata_worksheet.write_column('B1', data[1])
    rawdata_worksheet.write_column('C1', data[2])

    #Unprotected list worksheet
    unprotected_list_worksheet.write_row(0, 0, [unprotected_cve_list_title])
    for index, row in enumerate(unprotected_list):
        unprotected_list_worksheet.write_row(index+1, 0, row, workbook.add_format({'bold': index == 0}))

    #Rules Recom. for Assignment worksheet
    rule2assign_worksheet.write_row(0, 0, [recommended2assign_list_title])
    for index, row in enumerate(recommended2assign_list):
        rule2assign_worksheet.write_row(index+1, 0, row, workbook.add_format({'bold': index == 0}))

    #Rules Recom. for Unassignment worksheet
    rule2unassign_worksheet.write_row(0, 0, [recommended2unassign_list_title])
    for index, row in enumerate(recommended2unassign_list):
        rule2unassign_worksheet.write_row(index+1, 0, row, workbook.add_format({'bold': index == 0}))

    #Summary worksheet
    chart = workbook.add_chart({'type': 'column', 'subtype': 'percent_stacked'})
    chart.add_series({
        'name': '=Data!$B$1',
        'categories': '=Data!$A$2:$A$' + str(len(data[0])),
        'values':     '=Data!$B$2:$B$' + str(len(data[0])),
        'fill':   {'color': '#21BC3B'}
    })
    chart.add_series({
        'name': '=Data!$C$1',
        'categories': '=Data!$A$2:$A$' + str(len(data[0])),
        'values':     '=Data!$C$2:$C$' + str(len(data[0])),
        'fill':   {'color': '#C22828'}
    })
    chart.set_title ({'name': 'Recommendation scan results'})
    chart.set_x_axis({
        'name': 'Severity level',
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