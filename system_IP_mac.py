import subprocess as sp 
import re

def IP_address(interface):
    IPs = sp.check_output(['hostname', '-I']).decode().strip('')
    IP = IPs.split()[0]
    return IP

def mac_address(interface):
    result = sp.check_output(["ip",'link','show',interface])
    result = result.decode('utf-8')
    mac_address = re.search(r'link/ether ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', result).group(1)
    return mac_address
    
IP_address('ens33')
mac_address('ens33')

#\w\w:\w\w:\w\w:\w\w:\w\w:\w\w