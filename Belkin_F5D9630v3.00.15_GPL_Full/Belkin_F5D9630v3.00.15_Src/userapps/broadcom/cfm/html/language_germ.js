function dw(message)
{
	document.write(message);	
}

function assign_var()
{
// -------------- Menu ----------------
menu_1 = "Start";
menu_2 = "Hilfe";
menu_3 = "Anmelden";
menu_4 = "Abmelden";
menu_5 = "Internetstatus";
menu_6 = "Verbunden";
menu_7 = "Keine Verbindung";
menu_8 = "LAN-Konfigurierung";
menu_9 = "LAN-Einstellungen";
menu_10 = "DHCP-Client-Liste";
menu_11 = "Internet WAN";
menu_12 = "Verbindungstyp";
menu_13 = "DNS";
menu_14 = "Funknetz";
menu_15 = "Kanal und SSID";
menu_16 = "Sicherheit";
menu_17 = "Als Access Point verwenden";
menu_18 = "MAC-Adresskontrolle";
menu_19 = "Firewall";
menu_20 = "Virtuelle Server";
menu_21 = "Client-IP-Filter";
menu_22 = "DMZ";
menu_23 = "DDNS";
menu_24 = "WAN-Ping-Filter";
menu_25 = "Sicherheitsprotokoll";
menu_26 = "Dienstprogramme";
menu_27 = "Neustart Router";
menu_28 = "Werkseinstellungen wiederherstellen";
menu_29 = "Einstellungen Speichern/Sichern";
menu_30 = "Vorherige Einstellungen wiederherstellen";
menu_31 = "Firmware aktualisieren";
menu_32 = "Systemeinstellungen";
menu_33 = "Wi-Fi Protected Setup";
menu_34 = "Wireless Bridge";
		
// -------------- Home ----------------
home_1 = "Status";	
home_2 = "Um Einstellungen ändern zu können, müssen Sie sich anmelden.";
home_3 = "Verbinden";
home_4 = "Trennen";
home_5 = "Version";
home_6 = "LAN-Einstellungen";
home_7 = "Firmware-Version";
home_8 = "LAN/WLAN MAC";
home_9 = "Bootcode-Version";
home_10 = "IP-Adresse";
home_11 = "Hardware";
home_12 = "Subnet-Mask";
home_13 = "DHCP-Server";
home_14 = "Internet-Einstellungen";
home_15 = "Merkmale";
home_16 = "WAN MAC-Adresse ";
home_17 = "NAT";
home_18 = "WAN-IP";
home_19 = "Funknetzfunktion";
home_20 = "Standard-Gateway";	
home_21 = "SSID";	
home_22 = "Primärer DNS-Server";
home_23 = "Sicherheit";
home_24 = "Deaktiviert";
home_25 = "WEP";
home_26 = "WPA(mit Radiusserver)";
home_27 = "WPA-PSK(kein Server)";
home_28 = "Sekundärer DNS-Server";
home_29 = "ADSL";
home_30 = "Language";//<=====Dave=====
home_31 = "Typ";
home_32 = "Current Langugae";//<=====Dave=====
home_33 = "Status";
home_34 = "Available Langugaes";//<=====Dave=====
home_35 = "Verbindungsausfall";
home_36 = "Nachschaltung";
home_37 = "Vorschaltung";
home_38 = "Übertragungsrate";
home_39 = "Rausch-Marge";
home_40 = "Ausgabeleistung";
home_41 = "Dämpfung";
home_42 = "Einrichten Start";
home_43 = "Aktiv";
home_44 = "Deaktiviert";
home_45 = "English";
home_46 = "German";
home_47 = "Fran&ccedil;ais";
home_48 = "Español";
home_49 = "Funknetz-Einstellungen";
home_50 = "WLAN MAC-Adresse";
home_51 = "Zeit";
home_52 = "WPS";

// -------------- Login ----------------
lgn_1 = "Anmelden";
lgn_2 = "Um Einstellungen ändern zu können, müssen Sie sich mit einem Kennwort anmelden. Wenn Sie noch kein eigenes Kennwort eingestellt haben, können Sie dieses Feld leer lassen und auf \"Absenden\" klicken.";
lgn_3 = "Kennwort";
lgn_4 = "Vorgabe = leer lassen";
lgn_5 = "Löschen";
lgn_6 = "Absenden";

// -------------- LAN Main ----------------
lm_1 = "LAN";
lm_2 = "LAN";
lm_3 = "Ihr Router ist mit einem DHCP-Server ausgestattet, der jedem Computer im Netzwerk automatisch eine IP-Adresse zuweist. Die Werkseinstellungen für den DHCP-Server funktionieren für die meisten Anwendungen. Sie können die Einstellungen jedoch bei Bedarf verändern.";
lm_4 = "Folgende Änderungen können durchgeführt werden:";
lm_5 = "Ändern der internen IP-Adresse des Routers. Standardeinstellung = 192.168.2.1";
lm_6 = "Ändern der Subnet-Mask. Standardeinstellung = 255.255.255.0";
lm_7 = "DHCP-Serverfunktion aktivieren/deaktivieren. Vorgabe= AN (Aktiviert)";
lm_8 = "Einstellen der Start- und der Endadresse des IP-Pools. Vorgabe = Startadresse: 2 / Endadresse: 100";
lm_9 = "Vergabedauer für die IP-Adresse angeben. Vorgabe= Unbefristet";
lm_10 = "Lokalen Domänennamen angeben. Standard = Belkin";
lm_11 = "Zur Durchführung von Änderungen klicken Sie links in der Registerkarte \"LAN\" auf \"LAN-Einstellungen\".";
lm_12 = "Der Router stellt eine Liste aller Client-Computer bereit, die mit dem Netzwerk verbunden sind. Um die Liste abzurufen, klicken Sie links auf der Registerkarte \"LAN\" auf \"DCHP-Client-Liste\".";

// -------------- LAN Settings ----------------
ls_1 = "LAN";
ls_2 = "LAN-Einstellungen";
ls_3 = "Hier können Sie das LAN (Lokales Netzwerk) einstellen. Damit die Änderungen umgesetzt werden, müssen Sie auf die Schaltfläche \"Änderungen übernehmen\" unten auf dem Bildschirm klicken.";
ls_4 = "IP-Adresse";
ls_5 = "Details";
ls_6 = "Subnet-Mask";
ls_7 = "DHCP-Server ";
ls_8 = "An";
ls_9 = "Aus";
ls_10 = "Die DHCP-Serverfunktion erleichtert die Einrichtung eines Netzwerks, da jedem Computer eine IP-Adresse zugewiesen wird. Hier müssen keine Änderungen durchgeführt werden.";
ls_11 = "IP-Pool-Startadresse ";
ls_12 = "IP-Pool-Endadresse ";
ls_13 = "Lease Time (Vergabedauer)";
ls_14 = "Ein Stunde";
ls_15 = "Zwei Stunden";
ls_16 = "Halber Tag";
ls_17 = "Ein Tag";
ls_18 = "Zwei Tage";
ls_19 = "Eine Woche";
ls_20 = "Zwei Wochen";
ls_21 = "Unbefristet";
ls_22 = "Die Zeit, während der der DHCP-Server die IP-Adresse für die einzelnen Computer reserviert.";
ls_23 = "Lokaler Domänenname";
ls_24 = "optional";
ls_25 = "Funktion zur Benennung eines Netzwerks.";
ls_26 = "Änderungen aufheben";
ls_27 = "Änderungen übernehmen";
ls_28 = "Achten Sie darauf, dass Sie eine nicht routbare IP-Adresse wählen.  192.168.x.x (x steht für eine Zahl zwischen 0 und 255). 10.x.x.x (x steht für eine Zahl zwischen 0 und 255). 172.y.x.x (y steht für eine Zahl zwischen 16 und 31, x für eine Zahl zwischen 0 und 255).";
ls_29 = "Entweder haben Sie nicht alle Zahlen eingegeben, oder einige der eingegebenen Zahlen sind ungültig. Die Zahl im Eingabefeld muss zwischen 0 und 255 liegen.";
ls_30 = "Sie haben eine ungültige Nummer für die Subnetz-Maske eingegeben.";
ls_31 = "Die LAN IP-Adresse darf sich nicht im DHCP-Adresspool befinden.";
ls_32 = "Die IP-Endadresse muss größer sein als die IP-Startadresse.";
ls_33 = "Ungültiger lokaler Domänenname";
ls_34 = "Soll die LAN IP-Adresse wirklich geändert werden?";
ls_35 = "Bitte geben Sie die neue LAN-Adresse manuell in das Adressfeld in der Statusleiste Ihres Browsers ein.";
ls_36 = "Der kabellose Router wird neu gestartet, wenn Sie diese Änderung von einem kabellos eingebundenen Computer aus durchführen. Der Computer kann kurzzeitig vom Router getrennt werden.";
ls_37 = "Die eingegebene IP ist ungültig.";

// -------------- LAN DHCP ----------------
ld_1 = "LAN";
ld_2 = "DHCP";
ld_3 = "DHCP-Client-Liste";
ld_4 = "Auf dieser Seite werden IP-Adresse, Hostname und MAC-Adresse der einzelnen Computer angegeben, die mit dem Netzwerk verbunden sind. Wenn für einen Computer kein Hostname festgelegt ist, ist das entsprechende Hostnamen-Feld leer. Mit \"Aktualisieren\" können Sie die Liste aktualisieren.";
ld_5 = "IP-Adresse";
ld_6 = "Hostname";
ld_7 = "MAC-Adresse";
ld_8 = "Aktualisieren";

// -------------- WAN Main ----------------
wm_1 = "Internet WAN";
wm_2 = "WAN";
wm_3 = "Auf der Registerkarte \"Internet WAN\" richten Sie den Router für die Verbindung mit Ihrem Provider ein. Der Router kann die Verbindung zu fast jedem Provider-System herstellen, sofern Sie die Routereinstellungen an den Verbindungstyp anpassen. Für die Einrichtung des Routers zur Verbindung mit dem Provider klicken Sie links auf dem Bildschirm auf der Registerkarte \"Internet WAN\" auf \"Verbindungstyp\".";
wm_4 = "Unterstützte Verbindungstypen:";
wm_5 = "PPPoE";
wm_6 = "PPPoA";
wm_7 = "Dynamic/Fixed IP (1483 Bridge)";//<=====Dave=====
wm_8 = "Statische IP-Adresse ";
wm_9 = "Nur Modem (Gemeinsame Internetnutzung wird deaktiviert)";

// -------------- WAN Connection ----------------
wc_1 = "WAN";
wc_2 = "Verbindungstyp";
wc_3 = "Verbindungstyp wählen:";
wc_4 = "PPPoE";
wc_5 = "PPPoA";
wc_6 = "Dynamic/Fixed IP (1483 Bridge)";//<=====Dave=====
wc_7 = "Statische IP (IPoA)";
wc_8 = "Nur Modem (Gemeinsame Internetnutzung wird deaktiviert)";
wc_9 = "Weiter";

// -------------- WAN DNS ----------------
wd_1 = "WAN";
wd_2 = "DNS";
wd_3 = "Wenn Ihnen Ihr Internetanbieter (ISP) eine bestimmte DNS-Adresse zugewiesen hat, geben Sie die Adresse in diesem Fenster ein und klicken Sie auf \"Änderungen übernehmen\". ";
wd_4 = "Automatisch vom ISP";
wd_5 = "DNS-Adresse";
wd_6 = "Sekundäre DNS-Adresse ";
wd_7 = " DNS = DNS-Server (Domain Name Server). Server im Internet, der URLs (Universal Resource Links - Einheitliche Ortsangeber für Ressourcen) wie www.belkin.com zu IP-Adressen auflöst. ";
wd_8 = "Details";
wd_9 = "Änderungen aufheben";
wd_10 = "Änderungen übernehmen";
wd_11 = "Ungültige IP-Adresse. Die letzte Zahl kann nicht 0 oder 255 sein.";

// -------------- WAN Connection PPPoE ----------------
wcp_1 = "PPPoE / PPPoA";
wcp_2 = "PPPoE";
wcp_3 = "PPPoA";
wcp_4 = " Geben Sie die Daten für die PPPoA-Einstellungen unten ein, und klicken Sie auf \"Änderungen übernehmen\". ";
wcp_5 = " Geben Sie die Daten für die PPPoE-Einstellungen unten ein, und klicken Sie auf \"Änderungen übernehmen\". ";
wcp_6 = "Benutzername";
wcp_7 = "Kennwort";
wcp_8 = "Kennwort erneut eingeben";
wcp_9 = "Service Name (Dienstname)";
wcp_10 = "VPI / VCI";
wcp_11 = "Kapselung";
wcp_12 = "LLC";
wcp_13 = "VC/MUX";
wcp_14 = "MTU";
wcp_15 = "Lassen Sie die MTU-Einstellung unverändert, es sei denn, Ihr Provider verlangt ausdrücklich eine andere Einstellung als 1432.";
wcp_16 = "Verbindung nach  ";
wcp_17 = "Minuten ohne Aktivität unterbrechen.";
wcp_18 = "Statische IP-Adresse verwenden";
wcp_19 = "Geben Sie Ihren Benutzernamen ein.";
wcp_20 = "Bitte geben Sie das Kennwort ein.";
wcp_21 = "The password you entered do not match. Please enter your password and re-type the same password.";//<=====Dave=====

// -------------- WAN Connection Dynamic/Fixed IP  ----------------
wcd_1 = "Dynamic/Fixed IP (1483 Bridge)";//<=====Dave=====
wcd_2 = "WAN-IP-Adresse ist eine ungültige IP-Adresse.";
wcd_3 = "WAN-Subnet-Mask ist eine ungültige IP-Adresse.";
wcd_4 = "Standardroute ist eine ungültige IP-Adresse.";
wcd_5 = "Klicken Sie hier, um Ihre DNS-Einstellungen einzugeben";
wcd_6 = "Statische Standardroute verwenden:";
wcd_7 = "Geben Sie die Daten für die dynamische IP unten ein, und klicken Sie auf \"Änderungen übernehmen\".";
wcd_8 = "IP assigned by ISP";//<=====Dave=====
wcd_9 = "Ja";
wcd_10 = "No";//<=====Dave=====

// -------------- WAN Connection Static IP  ----------------
wcs_1 = "Statische IP (IPoA)";
wcs_2 = "Keine Auswahl für Standard-Gateway.";
wcs_3 = "Bitte geben Sie Ihre DNS-Adresseinstellungen im folgenden Bildschirm ein oder überprüfen Sie sie";
wcs_4 = "Geben Sie die Daten für die statische IP unten ein und klicken Sie auf \"Änderungen übernehmen\".";
wcs_5 = "Gateway IP Address";//<=====Dave=====
wcs_6 = "WAN-Schnittstelle verwenden:";
wcs_7 = "WAN IP-Adresse";


// -------------- WAN Connection Modem  ----------------
wcm_1 = "Nur Modem (Gemeinsame Internetnutzung wird deaktiviert)";
wcm_2 = "To enter your Modem settings, type in your information below and click \"Apply changes\".";//<=====Dave=====
wcm_3 = "Bridge-Dienst aktivieren";

// -------------- Wireless Main  ----------------
wlm_1 = "Funknetz";
wlm_2 = "Auf dieser Registerkarte können Sie die Funkeinstellungen des Routers bestimmen.";
wlm_3 = "Kanal und SSID";
wlm_4 = "Funkkanal und SSID (Name des kabellosen Netzwerks) einstellen.";
wlm_5 = "Sicherheit";
wlm_6 = "Sicherheitseinstellungen des kabellosen Netzwerks wie WPA- oder WEP-Einstellungen ändern.";
wlm_7 = "Als Access Point verwenden";
wlm_8 = "AP als Routerbetriebsmodus festlegen.";
wlm_9 = "MAC-Adresskontrolle";
wlm_10 = "Richten Sie eine Liste zulässiger Clients ein, denen Sie den Zugriff auf das kabellose Netzwerk entweder erlauben oder verwehren möchten.";
wlm_11 = "Easily setup and connect to a WPA-enabled 802.11 network with WPS-certified devices using either Personal Information Number(PIN) method or Push Button Configuration(PBC) method.";
wlm_12 = "Set up a list of MAC addresses that enable the interconnection of access points wirelessly.";

// -------------- Wireless Channel and SSID  ----------------
wlcs_1 = "Current Channel (Aktueller Kanal)   ";
wlcs_2 = "SSID-Feld darf nicht leer sein.";
wlcs_3 = "Hier können Sie die Funkeinstellungen des Routers ändern. Klicken Sie auf \"Änderungen übernehmen\", um die Einstellungen zu sichern.";
wlcs_4 = "Funkkanal";
wlcs_5 = "SSID";
wlcs_6 = "Funkmodus ";
wlcs_7 = "nur 802.11n";
wlcs_8 = "nur 802.11g";
wlcs_9 = "nur 802.11b";
wlcs_10 = "Aus";
wlcs_11 = "Bandwidth";//<=====Dave=====
wlcs_12 = "SSID rundsenden ";
wlcs_13 = "Geschützter Modus ";
wlcs_14 = "Auto";
wlcs_15 = "WMM";
wlcs_16 = "Disable Afterburner(wireless_wifi) for selection";//<=====Dave=====
wlcs_17 = "WMM No Acknowledgement";//<=====Dave=====

// -------------- Wireless Security None  ----------------
wlsn_1 = "Sicherheitsmodus";
wlsn_2 = "WPA-PSK(kein Server)";
wlsn_3 = "128 Bit-WEP";
wlsn_4 = "64 Bit-WEP";
wlsn_5 = "WPA(mit Radiusserver)";
wlsn_6 = "Hier können Sie Sicherheits-/Verschlüsselungseinstellungen konfigurieren. Die Sicherheitseinstellungen sollten aktiviert sein, damit die maximale Sicherheit im kabellosen Netzwerk gewährleistet werden kann. WPA (Wireless Protected Access) ermöglicht dynamische Änderungen der Schlüssel und bietet die sicherste Lösung. In Funknetzumgebungen, in denen nicht alle Geräte WPA unterstützen, sollte WEP (Wired Equivalent Privacy) verwendet werden.";

// -------------- Wireless Security WEP 64  ----------------
wlsw64_1 = "Entweder haben Sie nicht alle Hexadezimal-Ziffern eingegeben oder einige der eingegebenen Hexadezimal-Ziffern sind ungültig. Ein Hexadezimalzeichen ist entweder eine Zahl zwischen 0 und 9 oder ein Buchstabe zwischen A und F.";
wlsw64_2 = "Dies ist keine gültige Kennfolge";
wlsw64_3 = "Schlüssel 1";
wlsw64_4 = "Schlüssel 2";
wlsw64_5 = "Schlüssel 3 ";
wlsw64_6 = "Schlüssel 4";
wlsw64_7 = "Änderungen konnten nicht übernommen werden, weil das Funknetz deaktiviert ist.";
wlsw64_8 = "ACHTUNG:Um ein Hexadezimalpaar automatisch zu erstellen, aktivieren Sie das Feld links und geben Sie dort eine Kennfolge (Passphrase) ein."; 
wlsw64_9 = "Kennfolge";
wlsw64_10 = "Generieren";

// -------------- Wireless Security WEP 128  ----------------
wlsw128_1 = "(13 zweistellige Hexadezimalzahlen) ";

// -------------- Wireless Security WPA PSK  ----------------
wlswp_1 = "Der WPA-PSK-Schlüssel sollte aus 8 bis 63 ASCII-Zeichen oder 64 Hexadezimalziffern bestehen.";
wlswp_2 = "TKIP";
wlswp_3 = "AES";
wlswp_4 = "Authentifizierung ";
wlswp_5 = "WPA-PSK";
wlswp_6 = "WPA2-PSK";
wlswp_7 = "Verschlüsselungstechnik ";
wlswp_8 = "Pre-Shared Key (PSK)";
wlswp_9 = "WPA-PSK(kein Server)";
wlswp_10 = "Wireless Protected Access mit PSK (Pre-Shared Key): Der Schlüssel ist ein Kennwort, das entweder aus einem Wort, einem Satz oder eine Folge von Buchstaben und Zahlen besteht. Der Schlüssel muss zwischen 8 und 63 Zeichen lang sein und kann Leer- und Sonderzeichen oder nur 64 Hexadezimalzeichen (0-F) beinhalten. Jeder Client, der ins Netzwerk eingebunden wird, muss denselben Schlüssel verwenden (Pre-Shared Key: PSK). ";
wlswp_11 = "Verdeckter PSK ";
wlswp_12 = "WPA-PSK + WPA2-PSK";

// -------------- Wireless Security WPA Radius  ----------------
wlsr_1 = "Bitte RADIUS-Schlüssel eingeben.";
wlsr_2 = "WPA/WPA2-Enterprise (RADIUS)";
wlsr_3 = "Erweiterte Einstellung - Wireless Protected Access unter Verwendung eines Servers zur Verteilung der Schlüssel an die Clients: Bei dieser Option muss der Radiusserver in das Netzwerk eingebunden sein.";
wlsr_4 = "WPA-RADIUS";
wlsr_5 = "WPA2-RADIUS";
wlsr_6 = "Radius-Server ";
wlsr_7 = "Radius-Port ";
wlsr_8 = "Radius-Schlüssel ";
wlsr_9 = "Schlüsselintervall ";
wlsr_10 = "(Sekunden)";

// -------------- Wireless WPS  ----------------
wlwps_1 = "Wi-Fi Protected Setup(WPS)";
wlwps_2 = " Wi-Fi Protected Setup (WPS) is the industry standard method to simplify the security setup and management of Wi-Fi networks. You now can easily setup and connect to a WPA-enabled 802.11 network with WPS-certified devices using either Personal Information Number(PIN) method or Push Button Configuration(PBC) method. Legacy devices without WPS can be added to the network using the traditional manual configuration method. ";
wlwps_3 = "Personal Information Number(PIN) Method";
wlwps_4 = "Enter the PIN from the client device and click \"Enroll\". Then start WPS on the client device from it's wireless utility or WPS application within 2 minutes.";
wlwps_5 = "Enter Client Device PIN";
wlwps_6 = "If an external Registrar is available, you can also enter Router's PIN at the external Registrar. To change Router's PIN, click \"Generate New PIN\". Or click \"Restore Default PIN\" to reset the PIN to factory default.";
wlwps_7 = "Enroll";
wlwps_8 = "Generate New PIN";
wlwps_9 = "Restore Default PIN";
wlwps_10 = "Start PBC";
wlwps_11 = "Router PIN:";
wlwps_12 = "Push Button Configuration(PBC) Method";
wlwps_13 = " Push and hold the PBC button on your Router for 3 seconds. Then start PBC on the device you want to connect to the Router within 2 minutes.";
wlwps_14 = "Manual Configuration Method";
wlwps_15 = "For client devices without WPS, manually configure the device with the following settings:";
wlwps_16 = "Network Name (SSID):";
wlwps_17 = "Wireless Security";
wlwps_18 = "Network Authentication:";
wlwps_19 = "Data Encryption:";
wlwps_20 = "Network Key (PSK):";
wlwps_21 = "Configured";
wlwps_22 = "Not configured";
wlwps_23 = "Please run Belkin Security Assistant from CD or manually configure";
wlwps_24 = "Wi-Fi Protected Setup Message";
wlwps_25 = "Initiating - Please start WPS in client device within 2 minutes.";
wlwps_26 = "Success - The device is connected to the Router";
wlwps_27 = "In Progress - Please wait...";
wlwps_28 = "Error Detected - Please try again.";
wlwps_29 = "Invalid PIN! The device PIN is eight numeric digits. Please verify and enter again.";
wlwps_30 = "PIN checksum failed! Please verify and enter a valid PIN.";
wlwps_31 = "OK";
wlwps_32 = "Close";
wlwps_33 = "Cancel";

// -------------- Wireless AP mode  ----------------
wlap_1 = "Bitte geben Sie die LAN-Adresse manuell in das Adressfeld in der Statusleiste Ihres Browsers ein.";
wlap_2 = "Als Access Point verwenden";
wlap_3 = "Aktivieren";
wlap_4 = "Deaktivieren";
wlap_5 = "Achten Sie darauf, dass Sie eine nicht routbare IP-Adresse wählen. Beispiele für nicht routbare IP-Adressen 192.168.x.x (x steht für eine Zahl zwischen 0 und 255.) 172.y.x.x (y steht für eine Zahl zwischen 16 und 31, x für eine Zahl zwischen 0 und 255.) 10.x.x.x (x steht für eine Zahl zwischen 0 und 255.)";
wlap_6 = "IP-Adresse festlegen";

// -------------- Wireless MAC filter  ----------------
wlmac_1 = "MAC-Adresskontrolle";
wlmac_2 = "MAC-Adresse";
wlmac_3 = "Hinzufügen";

// -------------- Firewall Main  ----------------
fwm_1 = "Firewall";
fwm_2 = "Ihr Router ist mit einer Firewall ausgestattet, die Ihr Netzwerk vor einer Reihe häufig vorkommender Hacker-Attacken schützt, darunter PoD (Ping of Death) und DoS-Angriffe (Denial of Service). Sie können die Firewall bei Bedarf abschalten. Dadurch ist Ihr Netzwerk Angriffen nicht völlig schutzlos ausgeliefert; die Gefahr unbefugter Eingriffe wächst jedoch. Daher sollten Sie die Firewall weitmöglichst aktiviert lassen.";

// -------------- Firewall Virtual Sever  ----------------
fwvs_1 = "Virtuelle Server";
fwvs_2 = "Active Worlds";
fwvs_3 = "Age of Empires";
fwvs_4 = "Age of Empires-Erweiterung: The Rise of Rome";
fwvs_5 = "Age of Empires II-Erweiterung: The Conquerors";
fwvs_6 = "Age of Empires II: The Age of Kings";
fwvs_7 = "Age of Kings";
fwvs_8 = "Age of Wonders";
fwvs_9 = "Aliens vs. Predator";
fwvs_10 = "AOL Instant Messenger";
fwvs_12 = "Audiogalaxy Satellite";
fwvs_13 = "AUTH";
fwvs_14 = "Baldur's Gate";
fwvs_15 = "BattleCom";
fwvs_16 = "Battlefield Communicator";
fwvs_17 = "Black and White";
fwvs_18 = "Blizzard Battle.net";
fwvs_19 = "Buddy Phone";
fwvs_20 = "Bungie.net";
fwvs_21 = "Camerades";
fwvs_22 = "CART Precision Racing";
fwvs_23 = "Close Combat für Windows";
fwvs_24 = "Close Combat III: The Russian Front";
fwvs_25 = "Close Combat: A Bridge Too Far";
fwvs_26 = "Combat Flight Simulator 2: WWII Pacific Theater";
fwvs_27 = "Combat Flight Simulator: WWII Europe Series";
fwvs_28 = "Crimson Skies";
fwvs_29 = "CuSeeMe";
fwvs_30 = "Dark Reign 2";
fwvs_31 = "Delta Force 2";
fwvs_32 = "Delta Three PC to Phone";
fwvs_33 = "Descent 3";
fwvs_34 = "Descent Freespace";
fwvs_35 = "Diablo I";
fwvs_36 = "Diablo II";
fwvs_37 = "DialPad.Com";
fwvs_38 = "DirectX 7 Spiele";
fwvs_39 = "DirectX 8 Spiele";
fwvs_40 = "DNS-Server (Domain Name Server)";
fwvs_41 = "Doom";
fwvs_42 = "Dune 2000";
fwvs_43 = "Dwyco Videokonferenzen";
fwvs_44 = "Elite Force";
fwvs_45 = "Everquest";
fwvs_46 = "F-16";
fwvs_47 = "F-22 Lightning 3";
fwvs_48 = "F-22 Raptor";
fwvs_49 = "F22 Raptor (Novalogic)";
fwvs_50 = "Falcon 4.0";
fwvs_51 = "Fighter Ace II";
fwvs_52 = "Flight Simulator 2000";
fwvs_53 = "Freetel";
fwvs_54 = "FTP-Server";
fwvs_55 = "GNUtella";
fwvs_56 = "Golf 2001 Edition";
fwvs_57 = "Go2Call";
fwvs_58 = "Half Life";
fwvs_59 = "Half Life Server";
fwvs_60 = "Heretic II Server";
fwvs_61 = "I76";
fwvs_62 = "ICUII-Client";
fwvs_63 = "IPSEC";
fwvs_64 = "Ivisit";
fwvs_65 = "IRC";
fwvs_66 = "IStreamVideo2HP";
fwvs_67 = "KaZaA";
fwvs_68 = "Kohan Immortal Sovereigns";
fwvs_69 = "LapLink Gold";
fwvs_70 = "Links 2001";
fwvs_71 = "Lotus Notes Server";
fwvs_72 = "Mail (POP3)";
fwvs_73 = "Mail (SMTP)";
fwvs_74 = "MechCommander 2.0";
fwvs_75 = "MechWarrior 4";
fwvs_76 = "Media Player (Medienwiedergabe) 7";
fwvs_77 = "Midtown Madness 2";
fwvs_78 = "Mig 29";
fwvs_79 = "Monster Truck Madness 2";
fwvs_80 = "Motocross Madness 2";
fwvs_81 = "Motorhead Server";
fwvs_82 = "MSN Gaming Zone";
fwvs_83 = "MSN Messenger";
fwvs_84 = "Myth";
fwvs_85 = "Myth II Server";
fwvs_86 = "Myth: The Fallen Lords";
fwvs_87 = "Need for Speed";
fwvs_88 = "NetMech";
fwvs_89 = "Netmeeting 2.0, 3.0, Intel Video Phone";
fwvs_90 = "NTP-Protokoll (Network Time Protocol)";
fwvs_91 = "NNTP (News Server)";
fwvs_92 = "OKWeb";
fwvs_93 = "OKWin";
fwvs_94 = "Outlaws";
fwvs_95 = "Pal Talk";
fwvs_96 = "pcAnywhere v7.5";
fwvs_97 = "PhoneFree";
fwvs_98 = "Polycom ViaVideo H.323";
fwvs_99 = "Polycom ViaVideo H.324";
fwvs_100 = "PPTP";
fwvs_101 = "Quake";
fwvs_102 = "Quake II (Client und Server)";
fwvs_103 = "Quake III";
fwvs_104 = "Red Alert";
fwvs_105 = "RealAudio";
fwvs_106 = "Real Player 8 Plus";
fwvs_107 = "Rise of Rome";
fwvs_108 = "Roger Wilco";
fwvs_109 = "Rogue Spear";
fwvs_110 = "Secure Shell Server (SSH)";
fwvs_111 = "Secure Web Server (HTTPS)";
fwvs_112 = "ShoutCast";
fwvs_113 = "SNMP";
fwvs_114 = "SNMP-Trap";
fwvs_115 = "Speak Freely";
fwvs_116 = "StarCraft";
fwvs_117 = "Starfleet Command";
fwvs_118 = "StarLancer";
fwvs_119 = "SWAT3";
fwvs_120 = "Telnet-Server";
fwvs_121 = "TFTP";
fwvs_122 = "The 4th Coming";
fwvs_123 = "Tiberian Sun: C&C III";
fwvs_124 = "Total Annihilation";
fwvs_125 = "Ultima";
fwvs_126 = "Unreal Tournament";
fwvs_127 = "Urban Assault";
fwvs_128 = "VoxPhone 3.0";
fwvs_129 = "Warbirds 2";
fwvs_130 = "Web-Server (HTTP)";
fwvs_131 = "WebPhone 3.0";
fwvs_132 = "Westwood Online";
fwvs_133 = "Windows 2000 Terminalserver";
fwvs_134 = "X Windows";
fwvs_135 = "Yahoo Pager";
fwvs_136 = "Yahoo Messenger Chat";
fwvs_137 = "Alle Einträge sind belegt.\nBitte löschen Sie einige Einträge, und versuchen Sie es erneut.";
fwvs_138 = "Mit dieser Funktion können Sie externe (Internet-)Anfragen bei Diensten wie Web-Server (Port 80), FTP-Server (Port 21) oder andere Anwendungen über Ihren Router zum internen Netzwerk aktivieren.";
fwvs_139 = "Bitte eine Option auswählen";
fwvs_140 = "Löschen";
fwvs_151 = "Typ";
fwvs_152 = "Sollen alle Einträge gelöscht werden?";
fwvs_153 = "Soll der Eintrag gelöscht werden";


// -------------- Firewall Client IP filter  ----------------
fwcf_1 = "Client-IP-Filter";
fwcf_2 = "Sonntag";
fwcf_3 = "Montag";
fwcf_4 = "Dienstag";
fwcf_5 = "Mittwoch";
fwcf_6 = "Donnerstag";
fwcf_7 = "Freitag";
fwcf_8 = "Samstag";
fwcf_9 = "Quell-Adresse ist eine ungültige IP-Adresse.";
fwcf_10 = "Ziel-Port hat eine ungültige Port-Nummer oder einen ungültigen Port-Bereich.";
fwcf_11 = "Sie können den Router so einstellen, dass der Zugriff auf das Internet, E-Mails oder andere Netzwerkdienste auf bestimmte Tage und Uhrzeiten beschränkt wird.";
fwcf_12 = "Beides";
fwcf_13 = "Blockzeit";
fwcf_14 = "Stets";
fwcf_15 = "Blockieren";
fwcf_16 = "Tag";
fwcf_17 = "Zeit";
fwcf_18 = "Schnittstelle";

// -------------- Firewall DMZ  ----------------
fwdmz_1 = "DMZ";
fwdmz_2 = "Mit der DMZ-Funktion können Sie einen Computer festlegen, der von der NAT-Firewall ausgenommen werden soll. Das kann erforderlich sein, wenn die NAT-Funktion bei einer Anwendung Probleme verursacht, zum Beispiel bei einem Spiel oder einer Videokonferenzanwendung. Verwenden Sie diese Funktion nur zeitweise. Der DMZ-Computer ist nicht vor Hacker-Angriffen geschützt. Um einen Computer in den DMZ-Status zu versetzen, geben Sie die letzten Ziffern seiner IP-Adresse in das Eingabefeld unten ein, und wählen Sie \"Aktivieren\". Klicken Sie auf \"Änderungen übernehmen\", um die Änderung in Kraft zu setzen.";
fwdmz_3 = "IP-Adresse des virtuellen DMZ-Host";
fwdmz_4 = "Statische IP-Adresse ";
fwdmz_5 = "Private IP";

// -------------- Firewall DDNS  ----------------
fwddns_1 = "Fehlender Hostname.";
fwddns_2 = "Fehlender Domänenname.";
fwddns_3 = "Fehlender Benutzername.";
fwddns_4 = "Ungültige E-Mail-Adresse.";
fwddns_5 = "Fehlendes Kennwort.";
fwddns_6 = "Ungültiger Schlüssel.";
fwddns_7 = "DDNS";
fwddns_8 = "DDNS-Dienste (Dynamisches DNS) ermöglichen die Anwendung eines Domänennamens auch dann, wenn Ihre Internet-IP-Adresse dynamisch ist. Sie müssen sich für den DDNS-Dienst bei einem der aufgeführten DDNS-Dienste registrieren.";
fwddns_9 = "DDNS-Dienst";
fwddns_10 = "DDNS deaktiviert";
fwddns_11 = "DDNS-Status";
fwddns_12 = "Getrennt";
fwddns_13 = "Verbunden";
fwddns_14 = "Benutzername";
fwddns_15 = "Kennwort";
fwddns_16 = "Domänenname";
fwddns_17 = "E-Mail";
fwddns_18 = "Schlüssel";
fwddns_19 = "Dynamisches DNS aktualisieren";

// -------------- Firewall Wan Ping Blocking  ----------------
fwwpb_1 = "WAN-Ping-Filter";
fwwpb_2 = "ERWEITERTE FUNKTION! Sie können den Router so einstellen, dass er auf ICMP-Pings (Pings an der WAN-Schnittstelle) nicht reagiert. Dadurch erhöht sich Ihre Sicherheit.";
fwwpb_3 = "ICMP-Ping blockieren";

// -------------- Firewall Security Log  ----------------
fwsl_1 = "Sicherheitsprotokoll";
fwsl_2 = "Der Router protokolliert alle routerinternen Aktivitäten wie das An- und Abmelden von Computern und Versuche aus dem Internet, auf den Router zuzugreifen. Das Protokoll kann unten angezeigt werden.";
fwsl_3 = "Protokolldatei";
fwsl_4 = "Speichern";
fwsl_5 = "Löschen";

// -------------- Utility Main  ----------------
utm_1 = "Dienstprogramme";
utm_2 = "Auf dieser Seite können Sie verschiedene Parameter des Routers verwalten und Verwaltungsfunktionen durchführen.";
utm_3 = "Neustart Router";
utm_4 = " Wenn der Router nicht mehr fehlerfrei funktioniert, kann oft ein Neustart Abhilfe schaffen. Bei einem Neustart bleiben Ihre Konfigurationseinstellungen erhalten. ";
utm_5 = "Werkseinstellungen wiederherstellen";
utm_6 = "Mit dieser Option setzen Sie alle Routereinstellungen auf die Werkseinstellungen zurück. Es wird empfohlen, die aktuellen Einstellungen zu sichern, bevor Sie die Werkseinstellungen wiederherstellen.";
utm_7 = "Einstellungen Speichern/Sichern";
utm_8 = "Mit dieser Funktion können Sie die aktuelle Konfiguration sichern. Dadurch können Sie Ihre Konfigurierung später wiederherstellen, wenn die Einstellungen zwischenzeitlich verloren gehen oder geändert werden. Sie sollten die aktuelle Konfiguration sichern, bevor Sie eine Firmware-Aktualisierung durchführen.";
utm_9 = "Firmware aktualisieren";
utm_10 = "Von Zeit zu Zeit veröffentlicht Belkin neue Versionen der Router-Firmware. Firmware-Aktualisierungen enthalten verbesserte Funktionen und Lösungen für eventuelle Probleme.";
utm_11 = "Systemeinstellungen";
utm_12 = "Auf der Seite Systemeinstellungen können Sie ein neues Administratorkennwort festlegen,die Zeitzone einstellen, die Fernverwaltung aktivieren und die NAT-Funktion des Routers ein- oder ausschalten."; 
utm_13 = "Vorherige Einstellungen wiederherstellen";
utm_14 = "Über diese Option stellen Sie die zuvor gespeicherten Einstellungen wieder her.";

// -------------- Utility Reset  ----------------
utrst_1 = "Sind Sie sicher, dass Sie den Router neu starten möchten? Der Router-Neustart wirkt sich nicht auf die Konfiguration aus.";
utrst_2 = "Der Neustart des Routers dauert etwa 60 Sekunden. Bis zum Ende des Neustarts darf der Router nicht abgeschaltet werden.";
utrst_3 = "Neustart Router";
utrst_4 = "Bisweilen kann es notwendig sein, den Router zurückzusetzen oder neu zu starten, falls dieser nicht mehr erwartungsgemäß funktioniert. Bei einem Neustart bleiben die Konfigurationseinstellungen erhalten. Klicken Sie unten auf die Schaltfläche \"Neustart Router\", um den Router neu zu starten."; 

// -------------- Utility Factory Default  ----------------
utfd_1 = "Werkseinstellungen  wiederherstellen";
utfd_2 = "ACHTUNG: Ihre Einstellungen gehen dabei vollständig verloren! Möchten Sie den Vorgang fortsetzen?";
utfd_3 = "Die Wiederherstellung der Werkseinstellungen nimmt bis zu 60 Sekunden in Anspruch. Schalten Sie den Router während dieses Vorgangs nicht ab.";
utfd_4 = "Werkseinstellungen werden nicht wiederhergestellt. Einstellungen gehen nicht verloren!";
utfd_5 = "Mit dieser Option setzen Sie alle Routereinstellungen auf die Werkseinstellungen zurück. Es wird empfohlen, die aktuellen Einstellungen zu sichern, bevor Sie die Werkseinstellungen wiederherstellen. Um die Werkseinstellungen des Routers wiederherzustellen, klicken Sie auf die Schaltfläche \"Werkseinstellungen wiederherstellen\".";
utfd_6 = "Standardeinstellungen wiederherstellen";

// -------------- Utility Save/Backup settings  ----------------
utss_1 = "Aktuelle Einstellungen speichern/sichern ";
utss_2 = "Mit dieser Funktion können Sie die aktuelle Konfiguration sichern. Dadurch können Sie Ihre Konfigurierung später wiederherstellen, wenn die Einstellungen zwischenzeitlich verloren gehen oder geändert werden. Sie sollten die aktuelle Konfiguration sichern, bevor Sie eine Firmware-Aktualisierung durchführen.";
utss_3 = "Speichern";

// -------------- Utility Previous Settings  ----------------
utps_1 = "Vorherige Einstellungen wiederherstellen ";
utps_2 = "Die Einstellungen werden aktualisiert und der Router wird neu gestartet. Warten Sie eine Minute.";
utps_3 = "Möchten Sie die Wiederherstellung der Einstellungen fortsetzen?";
utps_4 = "Nach der Wiederherstellung der Einstellungen reagiert\nder Router bis zu einer Minute lang nicht auf Befehle.\nDies ist völlig normal. Währenddessen darf der Router nicht abgeschaltet werden.";
utps_5 = "Über diese Option stellen Sie die zuvor gespeicherten Einstellungen wieder her.";
utps_6 = "Wiederherstellen";

// -------------- Utility Firmware Update  ----------------
utfu_1 = "Firmware aktualisieren";
utfu_2 = "Nach aktueller Firmware suchen ";
utfu_3 = "Firmware suchen";
utfu_4 = "Die Software wird hochgeladen. Warten Sie eine Minute.";
utfu_5 = "Bitte geben Sie den Pfad der Aktualisierungsdatei an. Geben Sie hierzu Pfad und Namen der Datei ein oder klicken Sie auf \"Durchsuchen\", um die Datei zu suchen.";
utfu_6 = "Sind Sie sicher, dass Sie die Aktualisierung fortsetzen möchten?";
utfu_7 = "Am Ende der Aktualisierung reagiert der Router bis zu einer Minute lang nicht auf Befehle. Dies ist völlig normal. Schalten Sie den Router während dieser Zeit nicht ab, und führen Sie keinen Neustart durch.";
utfu_8 = "Von Zeit zu Zeit veröffentlicht Belkin neue Versionen der Router-Firmware. Firmware-Updates enthalten Verbesserungen und Lösungen für mögliche Probleme. Klicken Sie auf den Link unten, um zu überprüfen, ob für den Router neue Firmware verfügbar ist.";
utfu_9 = "HINWEIS: Bitte sichern Sie Ihre aktuellen Einstellungen, bevor Sie die Firmware-Version aktualisieren. <b><a  style=\"FONT-SIZE: 11px; color:#0066FF\" href=\"util_save.html\"> Klicken Sie hier,</a></b> um auf die Seite Aktuelle Einstellungen speichern/sichern zurückzukehren.";
utfu_10 = "Firmware-Version";
utfu_11 = "Aktualisieren der Firmware";
utfu_12 = "Update";
utfu_13 = "Firmware wird aktualisiert.";
utfu_14 = "UNTERBRECHEN SIE DEN ROUTER NICHT, SCHALTEN SIE IHN NICHT AB! Dies könnte dazu führen, dass der Router nicht mehr funktioniert.";

// -------------- Utility System Settings  ----------------
utsys_1 = "Systemeinstellungen";
utsys_2 = "Sonntag";
utsys_3 = "Montag";
utsys_4 = "Dienstag";
utsys_5 = "Mittwoch";
utsys_6 = "Donnerstag";
utsys_7 = "Freitag";
utsys_8 = "Samstag";
utsys_9 = "Januar";
utsys_10 = "Februar";
utsys_11 = "März";
utsys_12 = "April";
utsys_13 = "Mai";
utsys_14 = "Juni";
utsys_15 = "Juli";
utsys_16 = "August";
utsys_17 = "September";
utsys_18 = "Oktober";
utsys_19 = "November";
utsys_20 = "Dezember";
utsys_21 = "132.163.4.102-Nordamerika";
utsys_22 = "192.5.41.41-Nordamerika";
utsys_23 = "192.5.41.209-Nordamerika";
utsys_24 = "207.200.81.113-Nordamerika";
utsys_25 = "208.184.49.9-Nordamerika";
utsys_26 = "129.132.2.21-Europa";
utsys_27 = "130.149.17.8-Europa";
utsys_28 = "128.250.36.3-Australien";
utsys_29 = "137.189.8.174-Asien/Pazifik";
utsys_30 = "Internationale Datumsgrenze (Westen)";
utsys_31 = "Midway Island, Samoa";
utsys_32 = "Hawaii";
utsys_33 = "Alaska";
utsys_34 = "Pazifische Zeit, Tijuana";
utsys_35 = "Arizona, Mazatlan";//<=====Dave=====
utsys_36 = "Chihuahua, La Paz";//<=====Dave=====
utsys_37 = "Mountain Time";
utsys_38 = "Central America";//<=====Dave=====
utsys_39 = "Central Time";
utsys_40 = "Guadalajara, Mexico City, Monterrey";//<=====Dave=====
utsys_41 = "Saskatchewan";
utsys_42 = "Bogota, Lima, Quito";
utsys_43 = "Ostküstenzeit";
utsys_44 = "Indiana";
utsys_45 = "Atlantic Time";
utsys_46 = "Caracas, La Paz";
utsys_47 = "Santiago";
utsys_48 = "Neufundland";
utsys_49 = "Brasilien";
utsys_50 = "Buenos Aires, Georgetown";
utsys_51 = "Grönland";
utsys_52 = "Mittel-Atlantik";
utsys_53 = "Azoren";
utsys_54 = "Kapverdische Inseln";
utsys_55 = "Casablanca, Monrovia";
utsys_56 = "Greenwich Mean Time: Dublin, Edinburgh, Lissabon, London";
utsys_57 = "Amsterdam, Berlin, Bern, Rom, Stockholm, Wien";
utsys_58 = "Belgrad, Pressburg, Budapest, Ljubljana (Laibach), Prag";
utsys_59 = "Brüssel, Kopenhagen, Madrid, Paris";
utsys_60 = "Sarajevo, Skopje, Warschau, Zagreb";
utsys_61 = "West-Zentralafrika";
utsys_62 = "Athen, Istanbul, Minsk";
utsys_63 = "Bukarest";
utsys_64 = "Kairo";
utsys_65 = "Harare, Pretoria";
utsys_66 = "Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius";//<=====Dave=====
utsys_67 = "Jerusalem";//<=====Dave=====
utsys_68 = "Bagdad";
utsys_69 = "Kuwait, Riad";
utsys_70 = "Moskau, Sankt Petersburg, Wolgograd";
utsys_71 = "Nairobi";
utsys_72 = "Teheran";
utsys_73 = "Abu Dhabi, Maskat";
utsys_74 = "Baku, Tbilisi, Yerevan";//<=====Dave=====
utsys_75 = "Kabul";
utsys_76 = "Ekaterinenburg";
utsys_77 = "Islamabad, Karachi, Tashkent";//<=====Dave=====
utsys_78 = "Chennai, Kolkata, Mumbai, New Delhi";//<=====Dave=====
utsys_79 = "Kathmandu";//<=====Dave=====
utsys_80 = "Almaty, Novosibirsk";//<=====Dave=====
utsys_81 = "Astana, Dhaka";//<=====Dave=====
utsys_82 = "Sri Jayawardenepura";//<=====Dave=====
utsys_83 = "Rangoon";//<=====Dave=====
utsys_84 = "Bangkok, Jakarta, Hanoi";
utsys_85 = "Krasnoyarsk";//<=====Dave=====
utsys_86 = "Peking, Chongqing, Hongkong, Urumchi";
utsys_87 = "Irkutsk, Ulaan Bataar";//<=====Dave=====
utsys_88 = "Kuala Lumpur, Singapore";//<=====Dave=====
utsys_89 = "Perth";
utsys_90 = "Taipeh";
utsys_91 = "Osaka, Sapporo, Tokio";
utsys_92 = "Seoul";//<=====Dave=====
utsys_93 = "Jakutsk";
utsys_94 = "Adelaide";//<=====Dave=====
utsys_95 = "Darwin";//<=====Dave=====
utsys_96 = "Brisbane";
utsys_97 = "Canberra, Melbourne, Sydney";
utsys_98 = "Guam, Port Moresby";
utsys_99 = "Hobart";
utsys_100 = "Wladivostok";
utsys_101 = "Magadan";
utsys_102 = "Solomon Is., New Caledonia";//<=====Dave=====
utsys_103 = "Auckland, Wellington";
utsys_104 = "Fidschi, Kamtschatka, Marshallinseln";
utsys_105 = "Sonstige";
utsys_106 = "Kein(e)";
utsys_107 = "Es wird dringend empfohlen, ein Administratorkennwort festzulegen.";
utsys_108 = "Please choose the following remote management type :\n1.Any IP address can remotely manage the router\n2.Only this IP address can remotely manage the router";//<=====Dave=====
utsys_109 = "Ungültige Zahl! Gültig ist der Bereich 1 bis 65535";
utsys_110 = "Erster Zeit-Server  ist ein anderer; aber das Feld \"Andere\" ist leer.";
utsys_111 = "NTP IP Address is invalid IP address.";//<=====Dave=====
utsys_112 = "Zweiter Zeit-Server  ist ein anderer; aber das Feld \"Andere\" ist leer.";
utsys_113 = "Das alte Administrator-Kennwort ist falsch.";
utsys_114 = "Password should not be less than 3 characters or lognger than 12 characters.";//<=====Dave=====
utsys_115 = "Die Kennwörter stimmen nicht überein.";
utsys_116 = "Login Timeout should be between 1 and 99.";//<=====Dave=====
utsys_117 = "Administratorkennwort";
utsys_118 = "Der Router wird OHNE festgelegtes Kennwort geliefert. Sie können hier ein Kennwort festlegen und dadurch die Sicherheit erhöhen.";
utsys_119 = "Aktuelles Kennwort eingeben ";
utsys_120 = "Neues Kennwort eingeben ";
utsys_121 = "Neues Kennwort bestätigen ";
utsys_122 = "Anmeldezeitlimit ";
utsys_123 = "1-99 Minuten";
utsys_124 = "Uhrzeit und Zeitzone";
utsys_125 = "Bitte stellen Sie Ihre Zeitzone ein. Wenn in Ihrem Land zwischen Sommerzeit und Winterzeit umgeschaltet wird, markieren Sie dieses Feld";
utsys_126 = "Zeitzone";
utsys_127 = "Sommerzeit";
utsys_128 = "Sommerzeit automatisch einstellen";
utsys_129 = "Erster NTP-Zeitserver";
utsys_130 = "Zweiter NTP-Zeitserver";
utsys_131 = "Fernverwaltung";
utsys_132 = "ERWEITERTE FUNKTION! Die Fernverwaltung ermöglicht das Ändern Ihrer Routereinstellungen von jedem Ort aus, an dem sich ein Internet-Anschluss befindet. Bevor Sie diese Funktion aktivieren, SOLLTEN SIE UNBEDINGT EIN ADMINISTRATORENKENNWORT FESTLEGEN.";
utsys_133 = "Enable Remotely Management";//<=====Dave=====
utsys_134 = "Beliebige IP-Adresse zur Fernverwaltung des Routers";
utsys_135 = "Nur mit dieser IP-Adresse kann der Router fernverwaltet werden ";
utsys_136 = "Remote Access Port (Fernverwaltungsport)";
utsys_137 = "NAT-Aktivierung";
utsys_138 = "ERWEITERTE FUNKTION! Ermöglicht die Deaktivierung der NAT-Funktion. Normalerweise sollte diese Funktion NICHT deaktiviert werden.";
utsys_139 = "NAT aktivieren/deaktivieren";
utsys_140 = "UPnP";
utsys_141 = "ERWEITERTE FUNKTION! Ermöglicht Ihnen, die UPnP-Funktion an- oder abzuschalten.";
utsys_142 = "UPnP aktivieren";
utsys_143 = "Aktivieren der Automatischen Firmware-Aktualisierung";
utsys_144 = "ERWEITERTE FUNKTION! Ermöglicht Ihnen die automatische Suche nach Firmware-Aktualisierungen für den Router.";
utsys_145 = "Automatische Firmware-Aktualisierung Aktivieren / Deaktivieren";

// -------------- Check New Firmware  ----------------
cnf_1 = "Firmware suchen";
cnf_2 = "Kann keine Verbindung zum Firmware-Server herstellen,bitte überprüfen Sie die WAN-Verbindung."; 
cnf_3 = "Für diesen Router steht keine neue Firmware-Aktualisierung zur Verfügung.";

// -------------- Help  ----------------
hlp_1 = "Hilfe";
hlp_2 = "HELP OF TERMS";//<=====Dave=====
hlp_3 = "Nach oben";
hlp_4 = "Administrator";
hlp_5 = "Ein Administrator ist für die Wartung eines Netzwerks verantwortlich. Bei diesem Router die Person, die ihn einrichtet und seine Einstellungen verändert.";
hlp_6 = "Client";
hlp_7 = "Computer im Netzwerk, der die Dienste des Routers nutzt, zum Beispiel den automatischen DHCP-Server und die Firewall.";
hlp_8 = "DHCP";
hlp_9 = "Die DHCP-Serverfunktion erleichtert die Einrichtung eines Netzwerks, da jedem Computer eine IP-Adresse zugewiesen wird. Der DHCP-Server kann bei Bedarf deaktiviert werden. In diesem Fall müssen Sie auf jedem Computer im Netzwerk eine statische IP-Adresse manuell einstellen. Der IP-Pool ist die Reihe der IP-Adressen, die für eine dynamische Zuweisung an die Computer im Netzwerk reserviert sind. Die Vorgabe ist 2-100 (99 Computer). Wenn Sie diese Zahl ändern möchten, geben Sie eine neue Start- und eine neue End-IP-Adresse ein und klicken auf \"Änderungen übernehmen\".";
hlp_10 = "Lokaler Domänenname";
hlp_11 = "Sie können einen lokalen Domänennamen (Netzwerknamen) für Ihr Netzwerk festlegen. Diese Einstellung muss normalerweise nicht geändert werden, soweit Ihrerseits kein bestimmter Grund vorliegt. Sie können den Netzwerknamen frei wählen, z. B. \"MEIN_NETZWERK\".";
hlp_12 = "DFÜ-Verbindung";
hlp_13 = "Verbindung, die über das öffentliche Telefonnetz zustande kommt.";
hlp_14 = "DNS";
hlp_15 = "DNS ist die Abkürzung für Domain Name Server (Domänennamen-Server). Als DNS wird ein Server im Internet bezeichnet, der URLs (Universal Resource Locator) wie www.belkin.de zu IP-Adressen auflöst. Bei vielen Providern ist eine Eingabe dieser Informationen in den Router unnötig. Wenn Sie einen statischen Verbindungstyp festlegen, müssen Sie möglicherweise eine bestimmte DNS-Adresse sowie eine sekundäre DNS-Adresse angeben, damit die Verbindung ordnungsgemäß funktioniert. Wenn Sie mit einem dynamischen Verbindungstyp oder PPPoE arbeiten, müssen Sie wahrscheinlich keine DNS-Adresse eingeben.";
hlp_16 = "DSL-Modem";
hlp_17 = "DSL ist die Abkürzung von \"Digital Subscriber Line\" (Digitale Teilnehmerleitung). A DSL-Modems nutzen die vorhandene Telefonleitung zur Datenübertragung mit hoher Geschwindigkeit.";
hlp_18 = "Dynamische IP";
hlp_19 = "IP-Adresse, die von einem DHCP-Server automatisch zugewiesen wird.";
hlp_20 = "Ethernet";
hlp_21 = "Standard für Computernetzwerke. Ethernet-Netzwerke verbinden Computer durch spezielle Kabel und Hubs und ermöglichen Datenübertragungen mit bis zu 10 Millionen Bit pro Sekunde (Mbit/s)";
hlp_22 = "Firewall";
hlp_23 = "Elektronische Schwelle, die den Zugriff Unbefugter auf bestimmte Dateien oder Computer in einem Netzwerk verhindert.";
hlp_24 = "Firmware";
hlp_25 = "Software, die permanent im Arbeitsspeicher gespeichert ist. Wichtige Programme, die auch beim Abschalten des Systems im Speicher bleiben. Firmware kann leichter als Hardware verändert werden, ist aber dauerhafter als die Software auf einer Festplatte.";
hlp_26 = "IP-Adresse";
hlp_27 = "\"IP-Adresseist\" die interne IP-Adresse des Routers. Um die erweiterte Konfigurationsoberfläche zu öffnen, geben Sie diese IP-Adresse in die Adresszeile Ihres Browsers ein. Bei Bedarf können Sie die Adresse ändern. Geben Sie hierzu die neue IP-Adresse ein, und klicken Sie auf \"Änderungen übernehmen\". Achten Sie darauf, dass Sie eine nicht routbare IP-Adresse wählen. Beispiele für nicht routbare IP-Adressen: 192.168.x.x (x steht für eine Zahl zwischen 0 und 255.) 172.y.x.x (y steht für eine Zahl zwischen 16 und 31, x für eine Zahl zwischen 0 und 255.) 10.x.x.x (x steht für eine Zahl zwischen 0 und 255.)";
hlp_28 = "ISDN";
hlp_29 = "Integrated Services Digital Network. Digitale Telekommunikationsverbindungen, die sowohl Sprach- als auch digitale Netzwerkdienste bei Raten bis zu 128 K bieten. Sie sind wesentlich schneller und zuverlässiger als analoge Hi-Speed Verbindungen per Modem. ISDN-Leitungen werden in der Regel von Telefongesellschaften angeboten.";
hlp_30 = "Internet-Provider";
hlp_31 = "Internet Service Provider (Internet-Dienstanbieter, Provider). Der ISP stellt die Verbindung für Einzelpersonen, Unternehmen und Organisationen zum Internet bereit.";
hlp_32 = "ISP Gateway Address (Gateway-Adresse des Providers) (siehe auch ISP)";
hlp_33 = "Die ISP-Gateway-Adresse ist eine IP-Adresse für den Internet-Router des Providers. Diese Adresse wird nur für Kabel- oder DSL-Modems benötigt."; 
hlp_34 = "LAN";
hlp_35 = "Local Area Network (lokales Netzwerk). Als LAN wird eine Gruppe von Computern und Geräten bezeichnet, die auf relativ kleiner Fläche miteinander verbunden sind (zum Beispiel in einem Haus oder Büro). Ihr Netzwerk zu Hause ist ein solches LAN";
hlp_36 = "MAC-Adresse";
hlp_37 = " MAC steht für Media Access Control (Medienzugangskontrolle). MAC-Adresse ist die Bezeichnung für die Hardwareadresse eines Geräts, das mit einem Netzwerk verbunden ist";
hlp_38 = "MTU";
hlp_39 = "Maximum Transmission Unit (Maximale Übertragungsmenge). Die größte Datenmenge, die auf ein bestimmtes physikalischen Medium übertragen werden kann.";
hlp_40 = "NAT";
hlp_41 = "Network Address Translation (Netzwerkadressübersetzung). Durch dieses Verfahren können alle Computer in Ihrem Heimnetzwerk eine IP-Adresse gemeinsam nutzen. Durch die NAT-Funktionalität des Heimnetzwerk-Gateway-Routers von Belkin können alle Computer in Ihrem Heimnetzwerk auf das Internet zugreifen, ohne dass Sie mehrere IP-Adressen von Ihrem Provider beziehen müssen.";
hlp_42 = "Schnittstelle";
hlp_43 = "Logischer Kanal, der durch seine eindeutige Portnummer gekennzeichnet ist. Anwendungen warten an bestimmten Schnittstellen auf Daten, die für sie bestimmt sein könnten.";
hlp_44 = "Static IP Connection";//<=====Dave=====
hlp_45 = "Statische IP-Adressen werden seltener als andere Verbindungstypen verwendet. Falls Ihr Provider mit statischen IP-Adressen arbeitet, brauchen Sie die IP-Adresse, die Subnetz-Maske und die Provider-Gateway-Adresse. Diese Informationen erhalten Sie bei Ihrem Provider. Meistens sind sie in den Anmeldeunterlagen enthalten.";
hlp_46 = "PPPoE (Routing-Verfahren, für mehrere PCs)";
hlp_47 = "Die meisten DSL-Anbieter nutzen den Verbindungstyp PPPoE. Wenn Sie per DSL-Modem mit dem Internet verbunden sind, erfolgt die Anmeldung an den Service des Providers möglicherweise über PPPoE. Wenn Ihre Internetverbindung zu Hause oder im Büro ohne Modem auskommt, könnten Sie ebenfalls PPPoE verwenden. Ihr Verbindungstyp ist PPPoE, wenn folgende Voraussetzungen zutreffen: 1)Ihr Internetprovider hat Ihnen einen Benutzernamen und ein Passwort gegeben und diese Angaben sind zum Herstellen der Internetverbindung erforderlich. 2)Ihr Provider hat Ihnen für die Verbindung zum Internet bestimmte Software wie WinPOET oder Enternet300 bereitgestellt. 3)Sie müssen auf ein Desktop-Symbol doppelklicken (zusätzlich zum Browser), um ins Internet zu gelangen. Um den Router auf PPPoE einzurichten, geben Sie in den entsprechenden Feldern Ihren Benutzernamen und Ihr Kennwort ein. wenn der Router korrekt konfiguriert wurde. Weitere Informationen zur Konfigurierung des Routers für PPPoE finden Sie im Benutzerhandbuch. si su router ha sido configurado correctamente. Consulte el Manual de usuario si desea más información sobre cómo configurar su router para utilizar PPPoE.";
hlp_48 = "PPPoA";
hlp_49 = "Point-to-Point Protocol Over ATM. Using the PPP dial-up protocol with ATM as the transport. Used by some DSL providers, IP packets travel from the PC over Ethernet to the DSL modem. The DSL modem adds the PPP protocol to the IP packets and transports them to the carrier's DSLAM via ATM.";//<=====Dave=====
hlp_50 = "Zeitlimit";
hlp_51 = "Die Funktion \"Trennen\" dient zur automatischen Trennung des Routers vom Internet, wenn eine bestimmte Zeit lang keine Aktivität mehr festgestellt wird. Wenn Sie diese Option aktivieren und zum Beispiel 5 in das Minutenfeld eingeben, wird der Router nach fünf Minuten Inaktivität vom Internet getrennt. Diese Option sollte nur verwendet werden, wenn Ihre Internet-Nutzung nach Zeit abgerechnet wird.";
hlp_52 = "PPPoA (Routing-Verfahren, für mehrere PCs )";
hlp_53 = "Gemeinsame Internetnutzung deaktivieren (Bridging-Modus, für einzelnen PC)";
hlp_54 = "Mehrere Protokolle über ATM (Routing-Verfahren, für mehrere PCs)";
hlp_55 = "PPTP";
hlp_56 = "Point-to-Point Tunneling Protocol. Eine Version des PPP-Protokolls, das Datenpakete, die für ein bestimmtes Netzwerk formatiert wurden, zu Paketen für ein anderes Protokoll umformen kann. Durch dieses Tunnelverfahren können TCP/IP-Daten auch über TCP/IP-fremde Netzwerke übertragen werden. PPTP kann zur Vernetzung unterschiedlicher physikalischer Netzwerke mit dem Internet als Mittler dienen";
hlp_57 = "SNTP";
hlp_58 = "Simple Network Time Protocol. Kommunikationsstandard, der die Übertragung von Echtzeitdaten über ein Netzwerk oder das Internet ermöglicht";
hlp_59 = "SPI";
hlp_60 = " Stateful Packet Inspection (Paketstatus-Überprüfung). SPI ist die Bezeichnung für ein Internet-Sicherheitsverfahren in Industriequalität, das vom HomeConnect Heimnetz-Gateway bereitgestellt wird. Unter SPI dient der Gateway als Firewall, die Ihr Netzwerk vor Computerhackern schützt."; 
hlp_61 = "Statische IP-Adresse ";
hlp_62 = "IP-Adresse, die manuell konfiguriert wird und sich nicht ändert";
hlp_63 = "Subnet-Mask";
hlp_64 = "ERWEITERTE FUNKTION! Die Subnet-Mask muss nicht verändert werden. Bei Bedarf ist eine Änderung der Subnet-Mask möglich. Sie sollten sie jedoch nur dann verändern, wenn es hierfür einen bestimmten Grund gibt.";
hlp_65 = "TCP";
hlp_66 = "Transmission Control Protocol (Übertragungskontrollprotokoll). Das gängigste Protokoll für die Internet-Transportschicht. TCP ist verbindungsorientiert und datenstromorientiert und sorgt für zuverlässige Kommunikation über paketvermittelte Netzwerke.";
hlp_67 = "TCP/IP";
hlp_68 = "Transmission Control Protocol over Internet Protocol (Übertragungskontrollprotokoll/Internet-Protokoll). Das Standardprotokoll zur Datenübertragung im Internet.";
hlp_69 = "UDP";
hlp_70 = "User Datagram Protocol (Benutzer-Datagramm-Protokoll) Kommunikationsprotokoll für die Internet-Vermittlungsschicht, Transport- und Sitzungsschicht, das es möglich macht, eine Datagramm-Meldung von einem Computer an eine Anwendung zu versenden, die auf einem anderen Computer läuft. Anders als TCP ist UPD nicht verbindungsorientiert und gewährleistet keine zuverlässige Kommunikation. Die jeweilige Anwendung muss Fehler selbst verarbeiten und die Zuverlässigkeit der Datenvermittlung überprüfen.";
hlp_71 = "WAN";
hlp_72 = "Wide Area Network (Überregionales Netzwerk). Netzwerk, das Computer, die sich zum Beispiel in verschiedenen Gebäuden, Städten oder Ländern befinden, weiträumig miteinander verbindet. Das bekannteste Beispiel für ein WAN ist das Internet.";
hlp_73 = "WAN-IP-Adresse";
hlp_74 = "Die IP-Adresse, die der Provider dem Router zuweist.";
hlp_75 = "Kanal und SSID";
hlp_76 = "Sie können den Betriebskanal des Routers wechseln. Wählen Sie hierzu den gewünschten neuen Kanal aus dem Dropdown-Menü. Klicken Sie auf \"Änderungen übernehmen\" um die Einstellung zu speichern. Sie können auch die SSID ändern. Die SSID ist der Name des kabellosen Netzwerks. Sie können die SSID frei festlegen. Wenn sich in der näheren Umgebung weitere kabellose Netzwerke befinden, müssen Sie dem Netzwerk einen eindeutigen Namen zuweisen. Klicken Sie in das SSID-Feld und geben Sie einen neuen Namen ein. Klicken Sie auf \"Änderungen übernehmen\" um die Änderung zu speichern.";
hlp_77 = "Einstellen des Funkmodus";
hlp_78 = "1) 802.11g &amp; 802.11b : Setting the Router to this mode will let 802.11g-, and 802.11b-compliant devices to join the network. 2) Off : This mode will turn OFF the Router's access point, so no wireless devices can join the network. Turning off the wireless function of your Router is a great way to secure your network when you are away from home for a long period of time, or don't want to use the wireless feature of the Router at a certain time.";//<=====Dave=====
hlp_79 = "SSID rundsenden ";
hlp_80 = "Der kabellose Netzwerkadapter eines Computers kann normalerweise automatisch nach vorhandenen kabellosen Netzwerken suchen. Hierzu wird auf dem Adapter die SSID auf ANY (BELIEBIG) eingestellt Ihr Router kann diese Zufalls- Netzwerksuche blockieren. Wenn Sie die Funktion deaktivieren, erhält ein Computer nur Zugang zum Netzwerk, wenn die SSID des Computers auf den spezifischen Namen des Netzwerks (wie WLAN) eingestellt wird. Stellen Sie sicher, dass Sie Ihre SSID (Netzwerkname) kennen, bevor Sie diese Funktion verwenden. Sie können Ihr kabelloses Netzwerk fast unsichtbar machen. Wenn Sie das Rundsenden der SSID deaktivieren, wird Ihr Netzwerk nicht in Standortübersichten aufgenommen. Die Standortübersicht ist eine Funktion, mit der viele moderne kabellose Netzwerkadapter ausgestattet sind. Dabei wird die Luft nach vorhandenen Netzwerken abgesucht und gefundene Netzwerke werden zur Verbindung angeboten. Wenn Sie die Rundsendung der SSID deaktivieren, verbessern Sie die Netzwerksicherheit";
hlp_81 = "Als Access Point verwenden";
hlp_82 = "Wenn Sie den Router als Access Point verwenden, müssen Sie eine IP-Adresse für den Access Point festlegen. Die IP-Adresse muss sich im gleichen Bereich befinden wie das Netzwerk, zu welchem Sie eine Verbindung herstellen wollen. Um die erweiterte Konfigurierung des Routers erneut zu öffnen, geben Sie die IP-Adresse in den Browser ein und melden Sie sich an."; 
hlp_83 = "Funknetz MAC-Adressenkontrolle";
hlp_84 = "Der MAC-Adressfilter ist eine leistungsstarke Sicherheitsfunktion, mit der Sie festlegen können, welche Computer für das kabellose Netzwerk zugelassen sind. Hinweis: Diese Liste betrifft nur Computer mit kabellosem Zugang. Die Liste kann so eingestellt werden, dass jedem Computer, mit dem versucht wird, auf das Netzwerk zuzugreifen und der nicht in der Liste aufgeführt wird, der Zugang verweigert wird. Wenn Sie diese Funktion aktivieren, müssen Sie die MAC-Adresse eines jeden Clients (Computers) in Ihrem Netzwerk angeben, um den Netzwerkzugriff für diesen zu ermöglichen. Mit der Sperrfunktion \"Blockieren\" können Sie den Netzwerkzugriff für die einzelnen Computer bequem ein- oder ausschalten, ohne die MAC-Adressen in der Liste zu löschen oder hinzuzufügen.1. Erstellen einer Zugriffsliste Wählen Sie \"Allow\" (Erlauben) (1), um ein Liste der Computer zu erstellen, denen Sie den Zugang zum kabellosen Netzwerk erlauben.2. Geben Sie dann in ein freies Feld \"MAC address\" (3) (MAC-Adresse) die MAC-Adresse der kabellosen Computer ein, denen Sie den Zugang zum Funknetzwerk erlauben möchten und klicken Sie anschließend auf \"Add\" (4) (Hinzufügen).3. Fahren Sie so fort, bis alle Computer, denen Sie den Zugriff erlauben möchten, eingetragen sind.4. Klicken Sie auf \"Apply Changes\" (5) (Änderungen übernehmen), um den Vorgang zu beenden.<br><br>Erstellen einer Ausschlussliste n der \"Deny Access\"-Liste (Ausschlussliste) bestimmen Sie, welche Computer KEINEN Zugang zum Netzwerk haben sollen. Jedem Computer in dieser Liste wird der Zugang zum kabellosen Netzwerk verweigert. Alle anderen haben diesen Zugriff.1.Wählen Sie \"Deny\" (2) (Ausschließen), um ein Liste der Computer zu erstellen, denen Sie den Zugang zum kabellosen Netzwerk verweigern.2. Geben Sie dann in ein freies Feld \"MAC address\" (3) (MAC-Adresse) die MAC-Adresse der kabellosen Computer ein, denen Sie den Zugang zum Funknetzwerk verweigern möchten und klicken Sie anschließend auf \"Add\" (4) (Hinzufügen).3. Fahren Sie so fort, bis alle Computer, denen Sie den Zugriff verweigern möchten, eingetragen sind.4. Klicken Sie auf \"Apply Changes\" (Änderungen übernehmen) (5), um den Vorgang zu beenden."; 
hlp_85 = "ACK-Modus";
hlp_86 = "Es gibt zwei ACK-Modi (Acknowledgement - Empfangsbestätigung), die für die beste Multimedialeistung in Ihrem Netzwerk eingesetzt werden können: Burst ACK und Immediate ACK. Immediate ACK ist werksseitig voreingestellt und für den normalen Netzwerkbetrieb empfohlen. Die Änderung des ACK-Modus auf Burst ACK kann die Durchsatzraten beeinträchtigen. Verwenden Sie Immediate ACK, wenn Leistungen über längere Distanzen in Ihrem Netzwerk wichtig sind. Burst ACK wird die Raten vermindern, da nicht jedes im Netzwerk versendete Paket bestätigt wird. Bei einer sehr guten Verbindung zwischen dem Router und dem Client kann mit Burst ACK die Durchsatzleistung erhöht werden. Wenn für eine Anwendung, wie bei mehrfachen datenintensiven Videodatenströmen, eine hohe Bandbreite benötigt wird, verwenden Sie den Modus Burst ACK. Bedenken Sie, dass die Leistung über längere Distanzen in diesem Modus beeinträchtigt werden kann.";
hlp_87 = "QoS (Quality of Service)-Einstellung";
hlp_88 = "QoS schützt wichtigen Daten in Ihrem Netzwerk, wie Multimediainhalte und \"Voice over IP\" (VoIP), so dass diese nicht mit anderen im Netzwerk gesendeten Daten kollidieren. Auf der Grundlage von 802.11e kann diese Funktion nach Wahl aus- oder eingeschaltet werden. Wenn Sie Multimediainhalte oder VoIP in Ihrem Netzwerk verwenden, sollte die QoS-Funktion aktiviert sein.";
hlp_89 = "Verschlüsselung";
hlp_90 = "Using Encryption can help secure your wireless network. Only one type of security may be selected at a time. Therefore the customer must select a mode that is supported on all network devices on the wireless network. This Belkin product has 5 possible Security settings: 1) Disabled. No encryption is enabled in this mode. Open networks where all users are welcome sometimes prefer to not enable encryption. 2) WPA PSK - Home (no server). WPA (Wireless protected Access) PSK is a recent standards-based security technique where each packet of information is encrypted with a different code, or key. Since the key is constantly changing, WPA is very secure. There are two types of WPA, WPA-PSK (Pre-Shared Key), and WPA-Radius Server. Obviously the difference being that one requires a server and one does not. WPA-PSK is for home and small business users who do not have a server. The PSK encryption key is generated automatically from a string of characters or Pass Phrase. Obviously the biggest security risk in WPA PSK is if someone finds out your Pass Phrase. a. TKIP verses AES. WPA setup requires the user to select whether to encrypt using TKIP or AES. The WPA standard specifies TKIP, so that is the default. Additionally TKIP should provide better compatibility between wireless products from different vendors since many wireless products will never be upgraded to AES. AES is a new encryption technique based on the un-ratified 802.11i standard. New WPA standards are being considered using AES. Although AES is not as popular, some users may prefer to use this technique. Either way, all networks devices must use the same technique. b. Pre-Shared Key. Enter any word or phrase up to 40 characters. The same PSK must also be used for every other wireless network device on the network. Watch out for upper and lower case differences (\"n\" is different than \"N\".) Remember, the easiest way to break your security is for someone to guess your PSK. 3) 128-bit WEP. Until recently, 128-bit WEP (Wired Equivalent Privacy) was the standard for wireless encryption. If not all of your wireless devices support WPA, 128bit WEP still offers very good security option. It will require you to enter hex numbers, or you can generate them automatically. 4) 64-bit WEP. Belkin only recommends 64-bit mode on networks where some devices do not support either WPA or 128bit WEP. 5) WPA - Radius Server. (This mode is accessed from the Advanced Button). WPA server is only for networks using a Radius Server. All parameter for this mode should be obtained from the administrator of your Radius Server. Unlike WPA PSK, WPA server passes the key from the server to the clients instead of generating it automatically.";//<=====Dave=====
hlp_91 = "Virtuelle Server";
hlp_92 = "Mit dieser Funktion können Sie externe Aufrufe (aus dem Internet) von Diensten wie Webserver (Port 80), FTP-Server (Port 21) und andere Anwendungen über Ihren Router in das interne Netzwerk umleiten. Da Ihre internen Computer durch eine Firewall geschützt sind, kann auf diese aus dem Internet nicht zugegriffen werden, weil sie dort nicht \"Änderungen übernehmen\" sind. Wenn Sie die virtuelle Serverfunktion für eine bestimmte Anwendung einstellen müssen, sollten Sie Kontakt zum Hersteller des Programms aufnehmen, um dort zu erfahren, welche Port-Einstellungen Sie vornehmen müssen. Für die manuelle Eingabe geben Sie die IP-Adresse in das vorgegebene Feld für interne Geräte, den Port Typ (TCP oder UDP) sowie die LAN- und öffentlichen Ports, die passiert werden müssen ein; klicken auf Aktivieren und dann auf Einstellen Sie können pro interner IP-Adresse nur einen Port freigeben. Das Öffnen von Ports in Ihrer Firewall kann ein Sicherheitsrisiko darstellen. Das Aktivieren und Deaktivieren von Einstellungen geht schnell von der Hand. Daher sollten Sie die Einstellungen deaktivieren, wenn Sie eine bestimmte Anwendung momentan nicht verwenden. ";
hlp_93 = "Verwenden der dynamischen DNS";
hlp_94 = "Der dynamische DNS-Dienst ermöglicht es Ihnen, eine dynamische IP-Adresse in jeder der zahlreichen Domänen, die DynDNS.org anbietet, als statischen Hostnamen auszuweisen. Sie erlauben Ihren Netzwerkcomputern damit, leichter auf verschiedene Bereiche des Internets zuzugreifen. DynDNS.org bietet diesen Dienst für maximal fünf Hostnamen kostenlos im Internet an.Der Dynamische DNSSM-Dienst ist ideal für private Internetseiten, Dateiserver oder um den Zugriff zu Ihrem Heim-PC von Ihrem Arbeitsplatz aus zu erleichtern. Verwenden Sie den Dienst, wenn Sie sicher gehen möchten, dass Ihr Hostname immer zu Ihrer IP-Adresse führt, unabhängig davon, wie oft diese von Ihrem Provider geändert wird. Auch wenn sich Ihre IP-Adresse ändert, können Ihre Freunde und Bekannte sie immer im Internet finden, indem Sie ersatzweise die Adresse ihrname.dyndns.org eingeben!<br><br>Um sich kostenlos für Dynamic DNS anzumelden, öffnen Sie die Seite http://www.dyndns.org (englischsprachig).<br><Br><b>Einstellen des Update-Clients für Dynamisches DNS</b><br><br>Um sich kostenlos für Dynamic DNS anzumelden, öffnen Sie die Seite http://www.dyndns.org (englischsprachig).<br><br><b>Einstellen des Update-Clients für Dynamisches DNS</b><br><br>Sie müssen sich beim kostenlosen Aktualisierungsdienst von DynDNS.org anmelden, bevor Sie diese Funktion nutzen können. Nach der Registrierung befolgen Sie bitte diese Anweisungen.<Br>1.Geben Sie in das Feld \" User Name \" (1) (Benutzername) Ihren DynDNS.org-Benutzernamen ein.<Br>2.Geben Sie in das Feld \" Password \" (2) (Kennwort) Ihr DynDNS.org-Kennwort ein.<Br>3.Geben Sie in das Feld \" Domain Name \" (3) (Domänenname) den DynDNS.org-Domänennamen ein, den Sie mit DynDNS.org einstellt haben, ein.<br>4.Klicken Sie auf Update Dynamic DNS \" (Dynamisches DNS aktualisieren), um Ihre IP-Adresse zu aktualisieren. \" <Br>Immer wenn Ihre IP-Adresse vom Provider verändert wird, wird der Router automatisch die Server von DynDNS.org mit der neuen IP-Adresse aktualisieren. Sie können dies auch manuell tun, indem Sie auf die Schaltfläche \" Update Dynamic DNS \" (4) (Dynamische DNS aktualisieren) klicken."; 
hlp_95 = "Client-IP-Filter";
hlp_96 = " Sie können den Router so einstellen, dass der Zugriff auf das Internet, E-Mail oder andere Netzwerke zu einer bestimmten Zeit beschränkt wird. Die Beschränkung kann für einen einzelnen oder mehrere Computer festgelegt werden. Wenn Sie z.B. den Internet-Zugriff für einen bestimmten Computer einschränken möchten, geben Sie seine IP-Adresse in die IP-Felder ein. Geben Sie dann in die beiden Schnittstellenfelder jeweils 80 ein. Wählen Sie \"TCP\". Wählen Sie \"Blockieren\". Sie können auch \"Immer\" auswählen, um den Zugriff rund um die Uhr zu sperren. Wählen Sie oben den Starttag, und die Startzeit und den Endtag und die Endzeit unten. Klicken Sie auf \"Änderungen übernehmen\". Der Computer mit der angegebenen IP-Adresse wird jetzt zu den bestimmten Zeiten vom Internet-Zugriff ausgeschlossen. Hinweis: Achten Sie darauf, dass unter \"Dienstprogramme> Systemeinstellungen> Zeitzone\" die richtige Zeitzone ausgewählt ist.";
hlp_97 = "MAC-Adressfilter";
hlp_98 = "The MAC Address Filter is a powerful security feature that allows you to specify which computers are allowed on the network. Any computer attempting to access the network that is not specified in the filter list will be denied access. When you enable this feature, you must enter the MAC address of each client on your network to allow network access to each or copy the MAC address by selecting the name of the computer from the \"DHCP Client List\". To enable this feature, select \"Enable\". Next, click \"Apply Changes\" to save the settings.";//<=====Dave=====
hlp_99 = "DMZ";
hlp_100 = "If you have a client PC that cannot run an Internet application properly from behind the firewall, you can open the client up to unrestricted two-way Internet access. This may be necessary if the NAT feature is causing problems with an application such as a game or video conferencing application. Use this feature on a temporary basis. The computer in the DMZ is not protected from hacker attacks. To put a computer in the DMZ, enter the last digits of its LAN IP address in the Static IP field and click \"Apply Changes\" for the change to take effect.";//<=====Dave=====
hlp_101 = "Administratorkennwort";
hlp_102 = " Der Router wird OHNE festgelegtes Kennwort geliefert. Wenn Sie ein Kennwort hinzufügen möchten, um den Schutz Ihres Routers zu erhöhen, können Sie hier ein Kennwort eingeben. Bewahren Sie das Kennwort sicher auf. Sie benötigen es, wenn Sie sich künftig am Router anmelden möchten. Sie sollten ein Kennwort festlegen, wenn Sie die Fernverwaltung des Routers nutzen möchten. Mit dem Anmeldezeitlimit legen Sie fest, wie lange Sie an der Erweiterten Benutzeroberfläche für die Routerkonfiguration angemeldet bleiben können. Die Zähluhr startet, wenn keine Aktivität mehr registriert wird. Beispiel: Sie haben Änderungen mit der Erweiterten Benutzeroberfläche vorgenommen und verlassen ihren Arbeitsplatz, ohne auf \"Abmelden\" zu klicken. Angenommen, das Zeitlimit beträgt 10 Minuten, wird die Sitzung 10 Minuten, nachdem Sie den Computer verlassen haben, beendet. Wenn Sie weitere Änderungen vornehmen möchten, müssen Sie sich erneut am Router anmelden. Das Zeitlimit für die Anmeldung dient der Sicherheit und ist auf 10 Minuten voreingestellt. Hinweis: Es kann jeweils nur ein Computer an der erweiterten Konfigurationsoberfläche zur Routerkonfiguration angemeldet sein. ";
hlp_103 = "NAT-Aktivierung";
hlp_104 = " Bevor Sie diese Funktion aktivieren, SOLLTEN SIE UNBEDINGT EIN ADMINISTRATORKENNWORT FESTLEGEN. NAT (Netzwerkadressübersetzung) ist die Methode, mit der der Router die einzelne IP-Adresse, die Sie von Ihrem Internet-Provider erhalten haben, auf mehrere Computer im Netzwerk aufteilt. Diese Funktion sollte nur von erfahrenen Benutzern verwendet werden. Diese Funktion sollte nur verwendet werden, wenn der Provider Ihnen mehrere IP-Adressen zuteilt oder wenn Sie NAT zur weitergehenden Systemkonfigurierung abschalten müssen. Wenn Sie eine einzelne IP-Adresse haben und die NAT ausschalten, können die Computer im Netzwerk nicht mehr auf das Internet zugreifen. Zudem können weitere Probleme auftreten. Eine Deaktivierung von NAT schaltet die Funktionen der Firewall ab. ";
hlp_105 = "UPnP";
hlp_106 = "Die UPnP (Universal Plug-and-Play)-Technologie ermöglicht den reibungslosen Betrieb von Sprach-und Videonachrichten, Spielen und anderen Anwendungen, die dem UPnP-Standard entsprechen. Einige Anwendungen benötigen für eine einwandfreie Funktion eine spezielle Konfiguration der Firewall im Router. Hierzu müssen meistens TCP- und UDP-Ports geöffnet und in bestimmten Fällen auch Trigger-Ports gesetzt werden. UPnP-kompatible Anwendungen können mit dem Router kommunizieren und ihm mitteilen, wie die Firewall konfiguriert werden muss. Werkseitig ist die UPnP-Funktion des Routers deaktiviert. Wenn Sie UPnP-kompatible Anwendungen einsetzen und die UPnP-Funktionen nutzen möchten, können Sie die UPnP-Option aktivieren. Wählen Sie hierzu auf der Seite \"Dienstprogramme\" im Abschnitt \"UPnP-Aktivierung\" die Option \"Aktivieren\". Klicken Sie auf \"Änderungen übernehmen\", um die Änderung zu speichern.";
hlp_107 = "Automatische Benachrichtigung zur Firmware-Aktualisierung";
hlp_108 ="Der Router kann automatisch anfragen, ob eine neue Firmware-Version vorliegt und Sie ggf. darauf aufmerksam machen. Wenn Sie sich an der Erweiterten Benutzeroberfläche des Routers anmelden, überprüft der Router, ob neue Firmware verfügbar ist. Ist dies der Fall, werden Sie benachrichtigt. Sie können die neue Version herunterladen oder die Benachrichtigung ignorieren. Werkseitig ist diese Funktion des Routers deaktiviert. Wenn Sie sie aktivieren möchten, klicken Sie auf \"Aktivieren\" und dann auf \"Änderungen übernehmen\".";
hlp_109 = "Fernverwaltung";
hlp_110 = "Mit dem Fernmanagement können Sie überall vom Internet aus Änderungen an den Router-Einstellungen vornehmen. Für die Fernverwaltung des Routers gibt es zwei Methoden. Zum einen können Sie den Zugriff auf den Router vom gesamten Internet aus erlauben, in dem Sie die Funktion \" Beliebige IP-Adresse zur Fernverwaltung des Routers\" einstellen. Wenn Sie Ihre WAN-IP-Adresse von einem Computer mit Internetverbindung eingeben, sehen Sie einen Anmeldebildschirm, über den Sie das Kennwort für Ihren Router eingeben müssen. Zum anderen können Sie eine bestimmte IP-Adresse festlegen, an der Sie die Fernverwaltung des Routers durchführen möchten. Dies ist sicherer, aber auch unpraktischer. Geben Sie für diese Methode die IP-Adresse des Computers, an dem Sie den Router fernverwalten möchten, in das entsprechende Feld ein und aktivieren Sie die Option \"Nur diese IP-Adresse zur Fernverwaltung des Routers zulassen\". Es wird DRINGEND EMPFOHLEN, dass Sie ein Administratorkennwort festlegen, bevor Sie diese Funktion aktivieren. Wenn Sie auf das Kennwort verzichten, setzen Sie Ihren Router der Gefahr von Manipulationen durch Unbefugte aus.";
hlp_111 = "WLAN";
hlp_112 = "Wireless Local Area Network (lokales Funknetzwerk). Lokales Netzwerk, das Computer über Funk miteinander verbindet (zum Beispiel 802.11b)";
hlp_113 = "ICMP-PING BLOCKIEREN";
hlp_114 = "Computerhacker bedienen sich sogenannter \"Pings\", um potenzielle Opfer im Internet zu finden. Über die Ping-Prüfung einer IP-Adresse und die Antwort des adressierten Rechners kann ein Hacker Angriffspunkte feststellen. Der Router kann so eingerichtet werden, dass er auf ICMP-Pings von außen nicht antwortet. Hierdurch verbessern Sie den Schutz Ihres Routers. Um die Ping-Antwort abzuschalten, wählen Sie \"ICMP-Ping blockieren\" und klicken auf \"Änderungen übernehmen\". Der Router lässt jetzt ICMP-Pings unbeantwortet.";
hlp_115 = "Geschützter Modus ";
hlp_116 = "HINWEIS: Meistens wird die beste Durchsatzleistung erreicht, wenn der geschützte Modus deaktiviert ist. Wenn Sie in einer Umgebung mit INTENSIVEM 802.11b-Datenverkehr oder -Interferenzen arbeiten, wird die beste Durchsatzleistung erreicht, wenn der geschützte Modus eingeschaltet ist."; 
hlp_117 = "Uhrzeit und Zeitzone";
hlp_118 = " Der Router aktualisiert die Uhrzeit, indem er eine Verbindung mit einem Simple Network Time Protocol (SNTP)-Server herstellt. Dadurch kann der Router die Systemuhr mit dem weltweiten Internet synchronisieren Die synchronisierte Routeruhr dient zur Aufzeichnung des Sicherheitsprotokolls und zur Steuerung der Client-Filter. Wählen Sie die Zeitzone, in der Sie sich befinden. Wenn Sie sich in einer Region befinden, in der zwischen Sommer- und Winterzeit unterschieden wird, markieren Sie das Feld neben \"Sommerzeit aktivieren\" . Die Systemuhr wird nicht immer sofort aktualisiert. Sie müssen mindestens 15 Minuten abwarten, bis der Router die Zeitserver im Internet abfragt und eine Antwort erhält. Sie können die Uhr nicht selbst einstellen.";
hlp_119 = "Wi-Fi Multimedia (WMM)";
hlp_120 = "This feature enables the Quality of Service (QoS) function that is used for multimedia applications, such as Voice-over-IP (VoIP) and video. This allows the network packets of the multimedia application to have priority over regular data network packets, allowing multimedia applications to run smoother and with fewer errors.";
hlp_121 = "WMM No-Acknowledgement";
hlp_122 = "No-Acknowledgement refers to the acknowledge policy used at the MAC level. Enabling no-acknowledgement can result in more efficient throughput but higher error rates in a noisy Radio Frequency (RF) environment.";

// -- Restore factory defaults Successfully --
utfrds_1 = "Werkseinstellungen wiederherstellen";
utfrds_2 = "Das Wiederherstellen ist abgeschlossen, wenn die Betriebsanzeige nicht mehr aufblinkt.";

// -- Reset Successfully --
utrs_1 ="Zurücksetzen";
utrs_2 ="Das Zurücksetzen ist abgeschlossen, wenn die Betriebsanzeige nicht mehr aufblinkt.";
utrs_3 ="Router wird neu gestartet";
utrs_4 ="Restdauer in Sekunden.";


// -- Restored Settings Successfully --
utrss_1 ="Einstellungen wiederhergestellt";
utrss_2 ="Das Wiederherstellen der Einstellungen ist abgeschlossen, wenn die Betriebsanzeige nicht mehr aufblinkt.";

// -- Apply ?-
apply_1 = " Änderungen werden übernommen ";
apply_2 = "Änderungen werden übernommen. Bitte warten Sie...";


}
