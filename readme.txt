Aceasta app are ca scop analizarea traficului (Handshake TLS si FTP) in timp real si detecteaza alerte semnificative (aceasta aplicatie are in principal rol de monitorizare), precum detectarea extensii TLS nesigure, certificate expirate, detectare certificate auto-semnate sau certificate cu algoritmi slabi.

Aplicatia ruleaza cu urmatoarele module:

- pyshark, cryptography, tkinter, ipwhois, requests, abuseipdb;

Aplicatia are implementata API de la abuseipdb prin care verificam 10.000 ip-uri daca se afla in baza de date a acestora sau nu.

Aplicatia utilizeaza o interfata GUI, creata cu tkinter, care contine:

- butonul "Start" si "Stop" pentru a prelua trafic, respectiv a opri preluarea acestuia;
- sus se afla o bara de cautare (regex) prin care putem filtra logurile obtinute;
- jos se afla o bara de cautare a ip-urilor prin care aflam date despre acesta prin intermediul bibliotecii ipwhois;
- butonul "export" a logurilor;


Pentru testarea alertelor am folosit site-ul badssl.com pentru testarea certificatului expirat daca este parsat, iar in folderul "Testare alerte" am generat trafic fals cu ajutorul bibliotecii 
scapy* pentru a testa alertele de FTP.



