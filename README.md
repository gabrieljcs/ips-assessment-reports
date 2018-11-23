## Support
This is a community project and while you will see contributions from the Deep Security team, there is no official Trend Micro support for this project. The official documentation for the Deep Security APIs is available from the [Trend Micro Online Help Centre](http://docs.trendmicro.com/en-us/enterprise/deep-security.aspx). 

Tutorials, feature-specific help, and other information about Deep Security is available from the [Deep Security Help Center](https://help.deepsecurity.trendmicro.com/Welcome.html). 

For Deep Security specific issues, please use the regular Trend Micro support channels. For issues with the code in this repository, please [open an issue here on GitHub](https://github.com/deep-security/puppet/issues).

## Purpose
This project shows how users can integrate Deep Security’s intrusion prevention functionality into the vulnerability management flow with Deep Security SOAP APIs. The scripts give the ability to:

1. Make sure the deployment is successful.
   - Are Deep Security Agents installed? 
   - Is the intrusion prevention module turned on?
   - Are rules assigned on computers?
   
2. Obtain the Deep Security Recommendation Scan results.

3. List Deep Security intrusion prevention rules corresponding to Common Vulnerabilities and Exposures (CVEs).

4. Obtain additional Common Vulnerability Scoring System (CVSS) information, including severity, CVSS score, complete vector string, and so on.

5. Integrate with third-party vulnerability scanners.

Also, you can modify the python code to fit your own requirements.

## Requirements

#### Deep Security
All of the tasks in this repository assume you have a working Deep Security infrastructure. The key component is the Trend Micro Deep Security Manager.

You need enable SOAP API against your Deep Security Manager in advance. Please go to `Deep Security Manager: Administration > System Settings > Advanced` to enable Deep Security SOAP Web Service API.

Also, current supported versions are Deep Security 10.0 update 5, 11.0 update 1 and any version after 11.2.

#### python
In addition to the Deep Security infrastructure, the scripts need `python 3.x` and `pip`.

## Usage
1. Install all dependencies.

    `pip install -r requirements.txt`
    
2. Modify the `config.ini` for the environment.

3. Change the working directory to &lt;src&gt;
    
4. Generate `.csv` and `.xlsx` files to show the results.

    `python deployment_report.py`
    
    `python reco_scan_report.py`
    
    `python vulnerability_report.py`
    
    `python xlsx_report.py`
    
5. Check &lt;results&gt; for the results.

## Architecture
The diagram below shows how these scripts work.
![Flow Chart](/FlowChart.png)

## Modules

#### Integration
`deployment_report.py`, `reco_scan_report.py`, `vulnerability_report.py`: These scripts leverage `ds_utils.py` to generate the `Intrusion Prevention Deployment Report.csv`, `Intrusion Prevention Recommendation Scan Report.csv` and `Intrusion Prevention Vulnerability Report.csv`.

`xlsx_report.py`: This script transforms the `.csv` files to `.xlsx` format for readability.

#### Download CVE infomation from National Vulnerability Database (NVD)
The integration module gets additional CVSS information from NVD.

`nvd_downloader.py`: This file is responsible for downloading the database with CVE details (zipped JSON files) from the NVD website.

`nvd_parser.py`: This file is responsible for retrieving the essential fields from NVD.

#### Pre-process third-party report
Here we take `Qualys scan results` as example. The `report_parser.py` parses the scan results to `json` format.

Here is an example. It shows that two potential vulnerabilities (CVE-2016-3115, CVE-2016-10009) are identified in 10.0.0.1, and one vulnerability (CVE-2004-0230) is identified in 10.0.0.2.
```json
    {
        "10.0.0.1": {
            "vul_infos": [
                {
                    "cve_id": "CVE-2016-3115",
                    "third_party": {
                        "title": "OpenSSH Xauth Command Injection Vulnerability",
                        "qid": "38623",
                        "category": "General remote services",
                        "protocol": null,
                        "port": null,
                        "type": "PRACTICE"
                    }
                },
                {
                    "cve_id": "CVE-2016-10009",
                    "third_party": {
                        "title": "OpenSSH 7.4 Not Installed Multiple Vulnerabilities",
                        "qid": "38692",
                        "category": "General remote services",
                        "protocol": null,
                        "port": null,
                        "type": "PRACTICE"
                    }
                }
            ]
        },
        "10.0.0.2": {
            "vul_infos": [
                {
                    "cve_id": "CVE-2016-2183",
                    "third_party": {
                        "title": "Birthday attacks against TLS ciphers with 64bit block size vulnerability (Sweet32)",
                        "qid": "38657",
                        "category": "General remote services",
                        "protocol": "tcp",
                        "port": "3389",
                        "type": "VULN"
                    }
                }
            ]
        }
    }
```
If you want to integrate this project with other vulnerability scanners, you need to convert your scan reuslts to fit this format by either enhancing `report_parser.py` or implementing your own parser.
In addition, the _qid_, _category_ and _type_ are specifically for handling Qualys’ scan results. You can remove these attributes if you don't need them.

#### Folder structure
<pre>
\---root
    |
    |---config.ini
    |
    +---src
    |   |---deployment_report.py
    |   |---reco_scan_report.py
    |   |---vulnerability_report.py
    |   |---xlsx_report.py
    |   |
    |   +---ds_utils
    |       |---ds_utils.py
    |       |---nvd_downloader.py
    |       |---nvd_parser.py
    |       |---report_parser.py
    |       |---deployment2xlsx.py
    |       |---reco_scan2xlsx.py
    |       |---vulnerability2xlsx.py
    |
    +---nvd*
    |
    +---tmp
    |   |---ips_rules.json
    |   |---nvd.json
    |   |---report.json
    |
    +---vulnerabilities
    |   |---report.xml
    |
    +---results*
            
</pre>

Files and folders with a star ("*") suffix don't exist in the initial state. These files and folders are created automatically when executing this project.
* **config.ini:** The configuration file for the scripts
* **&lt;src&gt;:** The main working directory. All python scripts are located here.
* **&lt;ds_utils&gt;:** The utilities to generate reports.
* **&lt;nvd&gt;:** The folder contains the data feeds from NVD.
* **&lt;tmp&gt;:** The intermidate files are located here.
* **&lt;vulnerabilities&gt;:** Please put your third-party report into this folder, and save it as report.xml.
* **&lt;results&gt;:** The final results will be placed in this folder.
    
Copyright © 2018 Trend Micro Incorporated.  All rights reserved.
