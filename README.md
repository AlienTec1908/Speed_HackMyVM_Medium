# Speed - HackMyVM (Medium)
 
![Speed.png](Speed.png)

## Übersicht

*   **VM:** Speed
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Speed)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Speed_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Speed"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Entdeckung mehrerer Webdienste (Nginx auf Port 80, LiteSpeed WebAdmin auf 7080, LiteSpeed HTTP auf 8088). Eine LFI-Schwachstelle wurde in einer PHP-Anwendung auf Port 80 (`index.php?plot=`) gefunden. Die entscheidende Schwachstelle für den initialen Zugriff war eine Remote Code Execution (RCE) in einer veralteten Sar2HTML-Anwendung (Version 3.2.2, anfällig wie 3.2.1) auf Port 8088, die zu einer Shell als `www-data` führte. Für die Privilegieneskalation wurden LiteSpeed Admin-Credentials aus einer unsicher konfigurierten Datei (`adminpasswd`) ausgelesen. Eine authentifizierte RCE in der LiteSpeed WebAdmin Console führte laut Log zunächst zu einer Shell als `nobody`. Der finale Schritt zur Root-Eskalation erfolgte durch direkte Manipulation der `/etc/passwd`-Datei, um einen neuen Root-Benutzer anzulegen, wobei der genaue Weg zu den hierfür nötigen Schreibrechten im ursprünglichen Writeup nicht vollständig klar wird.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   `nikto`
*   `searchsploit`
*   `python3`
*   `nc` (netcat)
*   `ls`
*   `cat`
*   `base64`
*   `Burp Suite` (impliziert durch Parameter-Fuzzing/Analyse)
*   `find`
*   `id`
*   `openssl`
*   `echo`
*   `su`
*   `cd`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Speed" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.110`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 7.9p1), 80 (HTTP - Nginx 1.14.2), 7080 (SSL/HTTP - LiteSpeed WebAdmin Console), 8088 (HTTP - LiteSpeed, später als Sar2HTML identifiziert).
    *   Hinweis auf PHPSESSID-Cookie ohne HttpOnly-Flag auf Port 80.

2.  **Web Enumeration (Port 80 & 8088):**
    *   `gobuster` auf Port 80 fand `index.php` und `LICENSE`.
    *   `wfuzz` identifizierte die GET-Parameter `plot` und `delete` für `index.php` auf Port 80.
    *   Weitere `wfuzz`-Tests bestätigten eine Local File Inclusion (LFI)-Schwachstelle im `plot`-Parameter auf Port 80.
    *   Externe Hinweise/Enumeration identifizierten `phpinfo.php` und Sar2HTML Version 3.2.2 auf Port 8088 sowie eine veraltete PHP-Version (5.6.36).
    *   `searchsploit sar2html` fand einen RCE-Exploit (`49344.py`) für Sar2HTML 3.2.1, anwendbar auf die gefundene Version 3.2.2.

3.  **Initial Access (Sar2HTML RCE):**
    *   Ausnutzung der RCE-Schwachstelle in Sar2HTML auf Port 8088 mit dem Python-Skript `49344.py` und einem Netcat-Reverse-Shell-Payload.
    *   Erlangung einer interaktiven Shell als Benutzer `www-data`.

4.  **Post-Exploitation / Vorbereitung Privilege Escalation (von `www-data`):**
    *   Im Verzeichnis `/usr/local/lsws` wurde die welt-les- und schreibbare Datei `adminpasswd` gefunden.
    *   Inhalt: `admin/MjE0MGU2`. Dekodierung des Base64-Teils ergab das Passwort `2140e6` für den LiteSpeed WebAdmin-Benutzer `admin`.
    *   `searchsploit openLiteSpeed` fand einen authentifizierten RCE-Exploit (`49483.txt`) für OpenLiteSpeed 1.7.8.
    *   Versuch, die LiteSpeed RCE über die WebAdmin Console (Port 7080) mit den gefundenen Credentials und dem Exploit-Payload auszunutzen. Dies führte laut Log zu einer Shell als `uid=65534(nobody) gid=0(root)`, nicht direkt zu Root.

5.  **Privilege Escalation (zu `root` via `/etc/passwd` Manipulation):**
    *   *Der genaue Weg, wie die notwendigen Schreibrechte auf `/etc/passwd` erlangt wurden, ist im ursprünglichen Writeup an dieser Stelle nicht klar dokumentiert. Es wird angenommen, dass dies der erfolgreiche Pfad war, nachdem die LiteSpeed-RCE nicht direkt zu einer Root-Shell führte oder ein anderer, nicht dokumentierter Schritt erfolgte.*
    *   Generierung eines Passwort-Hashes für ein neues Passwort (im Beispiel "benni") mittels `openssl passwd`.
    *   Hinzufügen eines neuen Benutzereintrags (`bentec:[hash]:0:0:root:/root:/bin/bash`) zur Datei `/etc/passwd`.
    *   Erfolgreicher Login als der neue Benutzer `bentec` via `su bentec` (im Log wurde das Passwort `pass55` verwendet, was im Widerspruch zum generierten Hash für "benni" steht).
    *   Erlangung einer Shell mit `uid=0(root)`.

## Wichtige Schwachstellen und Konzepte

*   **Veraltetes Sar2HTML mit RCE:** Ausnutzung einer bekannten RCE-Schwachstelle (CVE für Version 3.2.1, anwendbar auf 3.2.2) in der Sar2HTML-Anwendung für den initialen Zugriff.
*   **Local File Inclusion (LFI):** LFI-Schwachstelle im `plot`-Parameter einer PHP-Anwendung auf Port 80.
*   **Unsichere Dateiberechtigungen:** Die LiteSpeed `adminpasswd`-Datei war welt-les- und schreibbar, was zur Kompromittierung der Admin-Credentials führte.
*   **Authenticated RCE in LiteSpeed WebAdmin:** Eine bekannte Schwachstelle erlaubte nach erfolgreicher Authentifizierung die Ausführung von Befehlen.
*   **Manipulation von `/etc/passwd`:** Direkte Modifikation der Passwortdatei zum Erstellen eines neuen Root-Benutzers (erfordert hohe, im Log nicht klar hergeleitete Privilegien).
*   **Veraltete PHP-Version (5.6.36):** Erhöht generell das Risiko für unentdeckte oder bekannte Schwachstellen.
*   **Fehlendes HttpOnly-Flag:** Das PHPSESSID-Cookie auf Port 80 wurde ohne das HttpOnly-Flag gesetzt.

## Flags

*   **User Flag (`/home/marvin/user.txt`):** `ilikemonkeysHMV`
*   **Root Flag (`/root/root.txt`):** `finallygotrootHMV`

## Tags

`HackMyVM`, `Speed`, `Medium`, `Sar2HTML`, `RCE`, `LFI`, `LiteSpeed`, `OpenLiteSpeed`, `/etc/passwd`, `PHP`, `Linux`, `Web`, `Privilege Escalation`
