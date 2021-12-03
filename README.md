# Flow-Monitoring
Monitors the flow of packets and extracts different things.

**Table of Contents**

[TOC]

# Dependencies
- C++ 11
- Libpcap (=>1.0.0)
- Cmake

# How to Build
Run `install.sh` script.
```bash
bash install.sh
```

# How to Run
Run `Flow-Monitoring` file in `Release` folder.
```bash
./Release/Flow-Monitoring [Interface Name]
```
After pressing Crtl+c, the output file will generate.


# TODO list
- Use config file.


# Sample Output
                    
Source IP  |  Dest IP |  Source Port | Dest Port | Protocols | Duration | Sent Bytes | Received Bytes | Header Bytes FWD
------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------
 74.125.133.189 | 192.168.43.116 | 56710 | 443 | TCP UDP | 1.376553 | 141 | 218 | 88
 192.168.43.116 | 94.182.96.125 | 41916 | 443 | TCP  | 188.852051 | 548206 | 47865469 | 421956

