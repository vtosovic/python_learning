#!/usr/bin/env python3
##
##
##Vladimir Tosovic

#from sys import argv
from sys import exit
#import pexpect
import re
import paramiko
import time
import subprocess
import getpass

#uvodni deo

print('Routing for Roaming tester')
print('Before test, make sure to copy content of mail from Roaming team to local file "roaming-input", WITHOUT entering senders signature!')
print('Please enter credentials for vsr-grx-bg1')
username = input('Username: ')
password = getpass.getpass('Password: ')

try:
#    username = input('Username: ')
#    password = input('Password: ')
    child = paramiko.SSHClient()
    child.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    child.connect('10.245.188.10', 22, username, password)
    session = child.invoke_shell()
    stdout = session.recv(65556)
    session.send('terminal length 0\n')
except paramiko.ssh_exception.AuthenticationException:
    print("Wrong username/password")
    exit()

print('Step 1 - Parsing roaming-input')

#pattern koji prepoznaje IP adresu, u formatu 192.168.0.0/24
ipaddrPattern = re.compile(r'((([0-9]?){3}\.([0-9]?){3})+/)([0-9]?){2}')

#pattern koji prepoznaje cetvorocifreni i petocifreni ASN
asnPattern = re.compile(r'([0-9]){4,5}')

#file u koji ce se uneti IP adrese iz ulaznog emaila
f1 = open('roam_IP_from_file', 'w+')
#file u koji ce se uneti AS iz ulaznog emaila
f2 = open('roam_AS_from_file', 'w+')

#lista svi ASN
listASN = []
#lista svih IP
listIP = []

#prolazi se linija po linija, pa se po sablonu prepoznaje IP adresa
#adresa se dodaje u listIP, kao element liste i upisuje u file f1
#f1 je roam_IP_from_file
with open('roaming-input') as f:
    for line in f:
        if re.search(ipaddrPattern, line):
            temp = ('show ip route ' + line)
            f1.write(temp)
            listIP.append([line.strip()])
            
#prolazi se linija po linija, pa se po sablonu prepoznaje ASN
#adresa se dodaje u listASN, kao element liste i upisuje u file f2
#f2 je roam_IP_from_file
with open('roaming-input') as f:
    for line in f:
        if re.search(asnPattern, line):
            temp1 = re.search(asnPattern, line)
            temp2 = temp1.group(0)
            temp = ('show run | i ' + temp2.strip() + '\n')
            f2.write(temp)
            listASN.append(temp2.strip())

f1.flush()
f2.flush()

print('Step 2 - Contacting Router and Getting Information, First Run')

#paramiko komande za pristup vsr-grx-bg1
child = paramiko.SSHClient()
child.set_missing_host_key_policy(paramiko.AutoAddPolicy())
child.connect('10.245.188.10', 22, username, password)
session = child.invoke_shell()
stdout = session.recv(65556)
session.send('terminal length 0\n')

#file u kome se sakuplja spisak postojecih ASN
f3 = open('roam_AS_from_router', 'w+')

#iz fajla f2 se cita ASN po ASN i upisuje u f3
with open('roam_AS_from_file') as f:
    for line in f:
        session.send(line)
        time.sleep(1)
        stdout = session.recv(16384)
        asnout = stdout.decode('utf-8')
        f3.write(asnout)
f3.flush()

#file u kome se sakuplja spisak postojecih IP
f4 = open('roam_IP_from_router', 'w+')

#iz fajla f1 se cita IP po IP i upisuje u f4
with open('roam_IP_from_file') as f:
    for line in f:
        session.send(line)
        time.sleep(1)
        stdout = session.recv(16384)
        ipout = stdout.decode('utf-8')
        f4.write(ipout)
f4.flush()
        
child.close()

print('Step 3 - Parsing Through IP and ASN output')

#u fajlu je output _sh run | i xxxxx_ pa se matchuje ASN
#ukoliko je show run pokazao ASN, onda se brise taj ASN iz listeASN
#na kraju ostaju samo ASN u listi koji ne postoje u sh run

with open('roam_AS_from_router') as f:
    for line in f:
        if "ios-regex" in line:
            temp1 = line.split('_')
            temp2 = temp1[1]
            temp3 = temp2.split('$')
            asn1out = temp3[0]
            if asn1out in listASN:
                listASN.remove(asn1out)
            else:
                continue

#ukloniti duple elemente
listASN = list(dict.fromkeys(listASN))                
                
#u fajlu je output _sh ip route xxxxx_ pa se matchuje sa tipicnim outputom
#ukoliko je show ip route pokazao da postoji ruta, brise se ta ruta iz listIP
#na kraju ostaju samo IP u listi kojih nema u ruting tabeli
with open('roam_IP_from_router') as f:
    for line in f:
        if "Routing entry for" in line:
            pattern1 = re.compile('Routing entry for (.*)')
            result1 = re.search(pattern1, line)
            ip1out = result1.group(1)
            listIP.remove([ip1out])

print('Step 4 - Creating Configuration File for ASNs')

#file koji sadrzi konfiguraciju za ASN koja se unosi na ruter
f5 = open('configASN', 'w+')
f5.write("edit as-path-set ebgp_AS_originators nano\n")
#prolazi se kroz listu ASN i kreira potreban unos prema IOS-XR
i=0
sizeoflist = len(listASN)
while i < sizeoflist:
    asntofile1 = listASN[i]
    asntofile2 = ("  ios-regex '_" + asntofile1 + "$',\n")
    f5.write(asntofile2)
    i += 1

f5.flush()

print('Step 5 - Contacting Router and Getting Information, Second Run')

#file koji sadrzi show run | i XXX/XX konfiguraciju ruta
f6 = open('roam_IP_from_router1', 'w+')

i=0
sizeoflist = len(listIP)
while i < sizeoflist:
    iptofile1 = listIP[i]
    iptofile2 = ("show run | i " + iptofile1[0] + '\n')
    f6.write(iptofile2)
    i += 1

f6.flush()

#pristup ruteru
child = paramiko.SSHClient()
child.set_missing_host_key_policy(paramiko.AutoAddPolicy())
child.connect('10.245.188.10', 22, username, password)
session = child.invoke_shell()
stdout = session.recv(65556)
session.send('terminal length 0\n')

#file koji sadrzi output komandi iz f6
f7 = open('roam_IP_from_router2', 'w+')

with open('roam_IP_from_router1') as f:
    for line in f:
        session.send(line)
        time.sleep(1)
        stdout = session.recv(16384)
        iplastout = stdout.decode('utf-8')
        f7.write(iplastout)
        
child.close()
f7.flush()

print('Step 6 - Parsing Through Router Output for Running Configuration')

#file u koji sadrzi konfiguraciju za ASN koja se unosi u ruter
f8 = open('configIP', 'w+')
f8.write("edit prefix-set ebgp_prefixes nano\n")
#proverava se format maske u show run i na osnovu toga se dobija IP adresa
#ukoliko IP adresa postoji, izbacuje se iz liste listIP
with open('roam_IP_from_router2') as f:
    for line in f:
        if 'le 32' in line:
            pattern2 = re.compile('  (.*) le 32,')
            result2 = re.search(pattern2, line)
            ip2out = result2.group(1)
            listIP.remove([ip2out])
        elif '/32,' in line:
            pattern3 = re.compile('  (.*),')
            result3 = re.search(pattern3, line)
            ip3out = result3.group(1)
            listIP.remove([ip3out])
        else:
            continue

#parsira se listIP i od nje pravi konfiguracioni fajl
#ukoliko je mreza /32, ne dodaje se le 32
#output se ispisuje u fajl
i=0
sizeoflist = len(listIP)
while i < sizeoflist:
    iptofile1 = listIP[i]
    if "/32" in iptofile1:
        iptofile2 = ("  " + iptofile1[0] + ',\n')
    else:
        iptofile2 = ("  " + iptofile1[0] + ' le 32,\n')
    f8.write(iptofile2)
    i += 1

f8.flush()

print('Step 7 - Configuration Files Ready')
print('Program completed')
print('File for ASN configuration - configASN')
print('File for IP configuration - configIP')

#subprocess.run(['notepad', 'configASN'])
#subprocess.run(['notepad', 'configIP'])