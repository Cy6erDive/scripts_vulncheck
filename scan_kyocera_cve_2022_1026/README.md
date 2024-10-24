
While many IT teams focus on more obvious network intrusions, printers and copiers often cascade down the list of priorities. The hackers know this. 

exp_kyocera.py - a little modified public exploit (Author: Aaron Herndon, @ac3lives (Rapid7))
scan_kyocera.py - scans network and checks if IP address is vulnerable to CVE-022-1026


[!] Port TCP 9091 should be accessible from your host\n
[!] There should be at least one record in address book of kyocera device

To run: 
```
python3 scan_kyocera.py 192.0.2.0/25
```

More about CVE-022-1026 - `h_ttps://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/`

