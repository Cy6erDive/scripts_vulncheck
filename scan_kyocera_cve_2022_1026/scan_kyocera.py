
from csv import reader, writer
import socket
import warnings
import argparse
from exp_kyocera import cve_kyocera
import ipaddress

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

#######
#
#Port TCP 9091 should be accessible
#In address book of kyocera device there should be at least one record for exploit to work
#To run: python3 scan_kyocera.py 192.0.2.0/25
#
##################

# Save results
def write_results(inlist, resultname):
    fileResults = open(resultname + '.csv', mode='w', encoding='utf8', newline='')
    resultwriter = writer(fileResults, delimiter=',')
    resultwriter.writerows(inlist)
    fileResults.close()


#Args
parser = argparse.ArgumentParser()
parser.add_argument("network", help="network to scan with CIDR, example: 192.0.2.0/25")
args = parser.parse_args()

net = args.network
result_data = [['#', 'IP', 'Result']]
target_network = ipaddress.ip_network(net)
socket.setdefaulttimeout(1) #Timeout in seconds to wait on socket - 9091
n = 0
for t in target_network.hosts():
    n += 1
    target = str(t)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    isopen = s.connect_ex((target, 9091))
    if isopen == 0:
        result = cve_kyocera(target)
    else:
        result = 'Timeout'
    result_data.append([n, target, result])

#Write results
write_results(result_data, 'results')

#Print vulnerable results
print(result_data[0:1])
for r in result_data[1:]:
    if r[2] == 'Vulnerable':
        print(r)
