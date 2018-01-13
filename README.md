# Proiect IC
#### Intercepting Mobile Communications: The Insecurity of 802.11


Link paper: http://www.isaac.cs.berkeley.edu/isaac/wep-draft.pdf

#### Testare:
* python test_wep.py

Proiectul pe care am ales sa il fac contine unele din atacuri posibile asupra protocolului WEP (Wired Equivalent Privacy). Odata cu raspundirea device-urilor care folosesc wireless-ul ca mijloc de conectare la internet si a fost nevoie de adoptarea unui protocol care sa ofere securitate sporita. Astfel, standardul 802.11 introduce WEP pentru protejarea confidentialitatii datelor userilor.

#### Descriere:
WEP foloseste o cheie secreta partajata de toti participanti la comunicare pentru a proteja mesajele.
Asa cum se observa si din imagine, plaintextul este format din mesaj si crc-ul acestuia. De precizat este faptul ca plaintext-ul nu este dependent de cheie.

In a doua parte, inainte de a cripta mesajul este obtinut keystream folosind algoritmul RC4, care este o functie de IV (vector de initializare) si cheie. Odata obtinut keystream-ul, urmatorul pas este xor intre plaintext si keystream pentru a obtine mesajul criptat, care este transmis cu IV folosit la RC4.

Scopul protocolului este de a preveni interceptarea si decriptarea de catre userii carora nu le este destinat mesajul (confidentialitate), oferirea protectiei la nivelul retelei wireless (controlul accesului) si prevenirea modificarii mesajelor (integritatea datelor), pentru acest lucru se foloseste crc-ul concatenat la mesaj.

#### Atacuri:
WEP ofera confidentialitate folosind un stream cipher, RC4. Stream cipher-ul expandeaza cheia secreta si IV intr-o secventa pseudorandom de biti. Mesajul criptat este transmis impreuna cu IV-ul pentru ca destinatarul mesajului sa poata genera la randul sau un keystream din cheie si IV. Folosind acelasi IV acesta obtine acelasi keystream, cu care este xorat mesajul criptat pentru a obtine mesajul initial.
O problema comuna a stream cipher-urilor este aceea ca folosirea aceluiasi IV si aceleasi chei duce la obtinerea aceluiasi keystream, si poate oferi informatii despre plaintext.

I. keystream reuse attack special case
- atunci cand se cunosc doua mesaje criptate cu aceeasi cheie si acelasi IV si se cunoaste si decriptarea unui mesaj dintre ele (mesajul in clar)
- obtinerea celui de-al doilea mesaj in clar se face astfel:
	- m2 = c1 ^ c2 ^ m1

II. keystream reuse attack
- atunci cand se cunosc doua mesaje criptate cu aceeasi cheie si acelasi IV
	- c1 = RC4(IV, key) ^ m1
	- c2 = RC4(IV, key) ^ m2

- aplicam xor si obtinem:
	- c1 ^ c2 = m1 ^ m2

- daca consideram ca mesajele sunt formate din cuvinte din dictionar putem folosi in atac de tip dictionary attack pentru a obtine cele doua mesaje in clar (aici am adoptat 2 strategii):
	#### II.1:
	- avand o lista cu cele mai uzuale cuvinte din dictionar (aprox. 60k) verific toate posibilitati in care un cuvant ar putea fi intr-unul dintre mesaje, verificand ca pe fiecare pozitie xorul rezultat sa fie egal cu xorul mesajelor criptate pe pozitia respectiva

	#### II.2:
	- primul pas pe care l-am facut a fost sa gasesc spatiile din xorul mesajelor criptate, astfel putem determina pozitiile unde pot aparea spatiile din mesajele initiale pentru a gasi lungimea cuvintelor
	- acum avem toate perechile de mesaje cu toate configuratiile in care pot aparea spatiile. Pentru fiecare doua cuvinte de pe pozitii echivalente caut in fisiere cuvintele de lungimea respectiva si verific daca xorate pe lungimea celui mai scurt cuvant sunt egale cu xorul mesajelor criptate pe aceleasi pozitii
	- adaug perechile de cuvinte gasite in mesaj si revin la pasul 2 pentru urmatoarele cuvante necunoscute din plaintext

- in cel de-al doilea caz, atacul nu o sa functioneze daca pe aceleasi pozitii din mesajele in 	clar sunt spatii pentru ca dupa xor valoare caracterul o sa fie 0, deci in cele doua mesaje ar putea fi orice caracter care se repeta pe aceeasi pozitie, dar avand in vedere ca cheia se 	schimba foarte rar si IV-ul are doar 24 de biti, deci 16 milioane de valori, sunt sanse foarte 	mari sa fie captate mesaje criptate cu aceeasi cheie si acelasi IV destul de multe intr-un 	interval de timp relativ scurt

#### Comparatie:
- cu metoda a doua (mai eficienta) pentru a obtine doua mesaje (35 de caractere) in clar a 	durat in jur de 2:30h, pe cand cu prima metoda (brute-force fara nicio optimizare) pentru a obtine doua mesaje (23 de caractere) ruleaza de 5 ore si inca nu s-a terminat.
	
Avand in vedere ca IV-ul are 24 de biti, un access point care trimite pachete de 1500 de bytes, la o latime medie de banda de 5 Mbps epuizeaza spatiul lui IV in 12 ore, aceasta vulnerabilitate este fundamentala si poate fi exploatata pentru a obtine keystream-ul cu care sunt criptate mesajele.

III. many time pad attack
- cand se presupune ca am captat un numar suficient de mare de mesaje criptate cu acelasi 	IV si aceeasi cheie
- pentru fiecare mesaj criptat xorat cu toate celelalte daca pe o pozitie rezultatul xorului este 	o litera atunci incrementez un contor
- daca pe un procent destul de mare (eu am folosit 70%) din xorurile unui mesaj criptat cu 	celelalte pe o anumita pozitie este o litera atunci inseamna ca spatiul se afla in mesajul 	curent -> valoarea keystream-ului de pe pozitia respectiva
- metoda asta nu gaseste valoarea keystream-ului pe o pozitie daca pe acea pozitie nu exista 	niciun spatiu in mesajele initiale sau exista prea multe spatii si numarul litere de pe o 	coloana este mai mic de 70% in acest caz
- odata gasit keystream-ul se pot decripta toate celelalte mesaje criptate cu aceeasi cheie si 	acelasi IV

Protocolul WEP foloseste pentru integritatea datelor un camp checksum pentru a se asigura ca mesajele nu sunt modificate de nimeni din exterior. Checksum-ul este un crc al mesajului, care este apoi concatenat la mesaj.
Folosind proprietatea checksum-ul, aceea ca este o functie liniara, putem modifica mesajul criptat fara a fi detectat din verificarea crc-ului (crc ramane valid pentru mesajul criptat modificat).

IV. message modification attack
- acest atac permite modificarea mesajului criptat astfel incat la decriptare sa rezulte alt 	mesaj fara a fi detectata modificare facuta
- este necesar un mesaj de aceeasi lungime cu mesajul criptat, delta, (in cazul asta delta = f0...00)
- la delta se concateneaza crc-ul sau, iar mesajul criptat modificat se obtine prin xor intre 	delta si mesajul criptat initial
- la decriptare mesajul obtinut este mesajul initial in clar xorat cu delta, crc-ul fiind valid
- acest atac functioneaza din cauza liniaritatii crc-ului si a faptului ca RC4 este un stream 	cipher, deci tot liniar (detalii in paper la sectiunea 4.1)
