#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lxml import html
import requests
import hashlib # Comes with Python.
import os
import re
from bs4 import BeautifulSoup # To get everything
import urllib2
from lxml import etree

def getOIDs():
	page = requests.get("https://en.wikipedia.org/wiki/Extended_Validation_Certificate#Extended_Validation_certificate_identification")
	tree = html.fromstring(page.text)

	items = tree.xpath("//*[@id=\"mw-content-text\"]/table[2]")
	dictionary = {}
	for i in items:
		for x in i:
			try:
				dictionary[x[0].text_content()]=x[1].text_content()
			except Exception, e:
				dictionary[x[0].text_content()]=[x[1].text_content()]
			
	clean = {}
	for k in dictionary.keys():
		clean[k] = dictionary[k].split()

	return clean
# print clean

# print getOIDs()
server = "google.com"
fingerPrintCommand = "echo R |openssl s_client -connect "+server+":443 2>/dev/null| sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' 2> /dev/null | openssl x509 -noout -in /dev/stdin -fingerprint -md5"




def getEVPolicyNumber(server, full=False):
	items = [("Issuer","O"), ("Policy")]
	fullCertCommand = "echo | openssl s_client -connect "+server+":443 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout "
	output = os.popen(fullCertCommand).read()
	uncleanBreak = output.split("\n")

	# print uncleanBreak
	goodList = {}
	OID = ""
	issuer = ""
	for line in uncleanBreak:
		if "policy" in line.lower():
			OID = line.split(":")[1].strip()
		if "issuer" in line.lower() and "o=" in line.lower():
			for x in line.split(":")[1].strip().split(","):
				if "O=" in x:
					issuer = x.split("=")[1]
	return OID,issuer

def isCertEv(oid):
	# OIDS = getOIDs()
	OIDS = ["1.3.6.1.4.1.34697.2.1","1.3.6.1.4.1.34697.2.2","1.3.6.1.4.1.34697.2.1 ","1.3.6.1.4.1.34697.2.3 ","1.3.6.1.4.1.34697.2.4","1.2.40.0.17.1.22","2.16.578.1.26.1.3.3","1.3.6.1.4.1.17326.10.14.2.1.2 ","1.3.6.1.4.1.17326.10.8.12.1.2","1.3.6.1.4.1.6449.1.2.1.5.1","2.16.840.1.114412.2.1","2.16.528.1.1001.1.1.1.12.6.1.1.1","2.16.840.1.114028.10.1.2","1.3.6.1.4.1.14370.1.6","1.3.6.1.4.1.4146.1.1","2.16.840.1.114413.1.7.23.3","1.3.6.1.4.1.14777.6.1.1 ","1.3.6.1.4.1.14777.6.1.2","1.3.6.1.4.1.22234.2.5.2.3.1","1.3.6.1.4.1.782.1.2.1.8.1","1.3.6.1.4.1.8024.0.2.100.1.2","1.2.392.200091.100.721.1","2.16.840.1.114414.1.7.23.3","1.3.6.1.4.1.23223.2 ","1.3.6.1.4.1.23223.1.1.1 ","1.3.6.1.5.5.7.1.1","2.16.756.1.89.1.2.1.1","2.16.840.1.113733.1.7.48.1","2.16.840.1.114404.1.1.2.4.1","2.16.840.1.113733.1.7.23.6","1.3.6.1.4.1.6334.1.100.1", "1.3.6.1.4.1.11129.2.5.1"]
	for k,v in getOIDs().items():
		for i in v:
			OIDS.append(i)
	OIDS = set(OIDS)
	for  idVal in OIDS:
		if oid in idVal:
			return True
	return False, oid

def getFingerPrint(server, remoteVerifier):
	fingerPrintCommand = "echo R |openssl s_client -connect "+server+":443 2>/dev/null| sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' 2> /dev/null | openssl x509 -noout -in /dev/stdin -fingerprint -sha1"
	remoteCommand = 'typeset -f | ssh -t '+remoteVerifier+' "'+fingerPrintCommand+'" 2> /dev/null'
	return os.popen(fingerPrintCommand).read(),os.popen(remoteCommand).read()

def doesFingerPrintMatch(server, remoteVerifier):
		result = getFingerPrint(server, remoteVerifier)
		if result[0] == result [1]:
			return True
		return False

if doesFingerPrintMatch("google.com", "root@joubin.me") and isCertEv(getEVPolicyNumber("google.com", True)[0]):
	print "Youre save. The site uses both EV and your hash matches the remote hash"
elif isCertEv(getEVPolicyNumber("google.com", True)[0]):
	print "The finger prints didnt match, but thats okay. The site uses EV"
else:
	print "run like hell dude/dudet. The hash is wrong and I was not able to validate EV"


