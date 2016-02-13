#!/bin/env python
# -*- coding: utf-8 -*-


"""

Hulp functie om BSN nummers te genereren.

Zowel De Belastingdienst als het Ministerie van Binnenlandse Zaken verklaren o.a. via hun websites dat er geen enkele betekenis achter het sofinummer schuilgaat. met andere woorden: uit (de opbouw van) het nummer is niets af te leiden over de houder(s) van het nummer.

Toch zijn er historisch wel enkele kenmerken over deze toekenning en de willekeurigheid ervan:

De nummers beginnend met 00 werden toegekend aan samenwerkingsverbanden als een VOF of een CV. Inmiddels krijgen deze ook nummers beginnend met een 8. De nummers beginnend met een 8 zijn toegekend aan niet-natuurlijke personen als BV's, NV's en fiscale eenheden en worden exclusief door de Belastingdienst uitgedeeld.
De nummers zijn in het begin uitgedeeld aan mensen op volgorde van toetreden tot de arbeidsmarkt. Zo komt het voor dat binnen een gezin de man vaak een lager nummer heeft dan de vrouw als de man werkte en de vrouw niet. Ook zit er een volgorde in het toekennen van nummers binnen een gezin. Broers en zussen die bij de invoering al geboren waren zullen vaak opeenvolgende nummers hebben waarbij alleen de laatste twee of drie cijfers verschillen.
Nummers beginnend met een 0 zijn doorgaans van oudere personen, hoewel deze nummers inmiddels hergebruikt worden en dus aan jongeren toegekend zijn.[bron?] De nummers beginnend met een 2 zijn doorgaans van mensen geboren na 1987, de nummers beginnend met een 3 aan mensen die na de serie 2 zijn geboren. De nummers beginnend met een 4, 5 en 6 zijn doorgaans toegekend aan nieuw-ingezetenen of mensen die van buitenaf de Nederlandse arbeidsmarkt betreden.



"""

import random
from stdnum import nl





def maak_reeks(lngt=9, start=1, einde=10):
	#maak en range en geef deze terug als 'string', geen 0 als begin meegeven maar wel verder in de range accepteren 
	#vraag een kleine hack
	num = ''.join(str([random.randrange(int(start), int(einde)) for _ in range(0, int(lngt))]).strip('[]')).replace(', ', '')
	if num.startswith('0'):
		return maak_reeks(lngt, start, einde)
	else:
		return num

def maak_bsn(start=1, einde=10):
	num = maak_reeks(9, int(start), int(einde))
	if nl.bsn.is_valid(num):
		return num
	else:
		return maak_bsn(start, einde)

def maak_bsn_reeks(aantal=10, start=1, einde=10):
	terug = []
	for x in range(0,int(aantal)):
		terug.append(maak_bsn(start,einde))
	return terug

def kansberekening(aantal):
	#driedeuren probleem
	a = 1

def stactrace(aantal):
	#grafiek maken
	a = 1

	

#voorbeelden
print maak_reeks()
print "bsn"
print maak_bsn(2)
print maak_bsn_reeks(12,0,11)

