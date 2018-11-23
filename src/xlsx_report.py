# -*- coding: utf-8 -*-
# Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
"""Conver each csv files to xlsx format"""
import os

from ds_utils import deployment2xlsx, reco_scan2xlsx, vulnerability2xlsx

RESULT_PATH = "../results/"

def main():
    """Main function"""

    csv_file = os.path.join(RESULT_PATH, 'Intrusion Prevention Deployment Report.csv')
    xlsx_file = os.path.join(RESULT_PATH, 'Intrusion Prevention Deployment Report.xlsx')
    if os.path.isfile(csv_file):
        deployment2xlsx.parse(csv_file, xlsx_file)

    csv_file = os.path.join(RESULT_PATH, 'Intrusion Prevention Recommendation Scan Report.csv')
    xlsx_file = os.path.join(RESULT_PATH, 'Intrusion Prevention Recommendation Scan Report.xlsx')
    if os.path.isfile(csv_file):
        reco_scan2xlsx.parse(csv_file, xlsx_file)

    csv_file = os.path.join(RESULT_PATH, 'Intrusion Prevention Vulnerability Report.csv')
    xlsx_file = os.path.join(RESULT_PATH, 'Intrusion Prevention Vulnerability Report.xlsx')
    if os.path.isfile(csv_file):
        vulnerability2xlsx.parse(csv_file, xlsx_file)



if __name__ == "__main__":
    main()
