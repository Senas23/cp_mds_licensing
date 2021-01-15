# cp_mds_licensing
Get gateways count per type (Single, Cluster, VSX) per Domain (CMA) in a Multi-Domain Security Management (MDSM) environment

## Content
`cpapi` - Check Point Management API Python SDK v1.12

## Instructions
### Repository install from a remote machine
Install the repository by using the pip tool or by downloading the repository.

#### Install with pip
Run:
```
pip install git+https://github.com/Senas23/cp_mds_licensing
```

#### Download the repository
Clone the repository with this command:
```
git clone https://github.com/Senas23/cp_mds_licensing
```
or by clicking on the _‘Download ZIP’_ button and using unzip. <br>

#### cpapi from Check Point Management API Python SDK
Based on the instructions from the CheckPointSW/cp_mgmt_api_python_sdk, download the repository and copy the `cpapi` folder into your extracted folder. Currently used `cp_mgmt_api_python_sdk` version is v1.12
```
https://github.com/CheckPointSW/cp_mgmt_api_python_sdk/
```

#### Check Point Management API Call Documentation
```
https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/show-gateways-and-servers~v1.6
```

### Usage
Either run the `process.py` without arguments/parameters and you will be asked for the IPv4/Hostname/FQDN of the Check Point Manamgement Server (SMS/MDS), or run `process.py` with an argument of the path to JSON file for offline processing that has the output of the `show gateways-and-servers` API against the Check Point Management Server in JSON format.

#### Set user execute permission
Run:
```
chmod u+x process.py
```

#### Execute without args/params and you will be asked for inputs to where to connect and which credentials to use
Run:
```
./process.py
```

#### Execute with paramters for offline processing of the output that is in JSON format
Run:
```
./process.py </path/to/file.json>
```

#### Sample output
```
Domain: Prod
  SingleGW: 0    ClusterXL: 2   VS: 100   StandbyMDS: True
  TotalCount: 102
Domain: Dev
  SingleGW: 3    ClusterXL: 2   VS: 5     StandbyMDS: True
  TotalCount: 10
Domain: Lab
  SingleGW: 2    ClusterXL: 2   VS: 5    StandbyMDS: False
  TotalCount: 9
Primary MDS Total GWs: 121      Standby MDS Total GWs: 112
```

## Development Environment
The kit is developed using Python version 3.6<br>
Tested against MDS (Multi Domain Server) with Management API v1.6
