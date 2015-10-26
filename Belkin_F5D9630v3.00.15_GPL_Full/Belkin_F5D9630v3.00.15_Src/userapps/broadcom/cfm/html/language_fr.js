function dw(message)
{
	document.write(message);	
}

function assign_var()
{
// -------------- Menu ----------------
menu_1 = "Accueil";
menu_2 = "Aide";
menu_3 = "Connexion";
menu_4 = "Déconnexion";
menu_5 = "Statut d'Internet";
menu_6 = "Connecté";
menu_7 = "Pas de connexion";
menu_8 = "Mise en place du réseau local (LAN)";
menu_9 = "Paramètres de réseau local";
menu_10 = "Liste de Clients DHCP";
menu_11 = "Internet WAN";
menu_12 = "Type de Connexion";
menu_13 = "DNS";
menu_14 = "Sans Fil";
menu_15 = "Canal et SSID";
menu_16 = "Sécurité";
menu_17 = "Utilisation comme Point d'accès";
menu_18 = "Contrôle d'adresse MAC";
menu_19 = "Pare-feu";
menu_20 = "Serveurs Virtuels";
menu_21 = "Filtres d'IP des clients";
menu_22 = "Zone DMZ";
menu_23 = "DDNS";
menu_24 = "Blocage du ping WAN";
menu_25 = "Journal de sécurité";
menu_26 = "Utilitaires";
menu_27 = "Redémarrer le Routeur";
menu_28 = "Rétablir les paramètres par défaut";
menu_29 = "Sauvegarder les paramètres";
menu_30 = "Rétablir les paramètres précédents";
menu_31 = "Mise à jour du micrologiciel";
menu_32 = "Paramètres du système";
menu_33 = "Wi-Fi Protected Setup";
menu_34 = "Wireless Bridge";
		
// -------------- Home ----------------
home_1 = "Statut";	
home_2 = "Vous devez ouvrir une session avant d'apporter des modifications.";
home_3 = "Connexion";
home_4 = "Déconnexion";
home_5 = "Information sur la version";
home_6 = "Paramètres de réseau local";
home_7 = "Version du microprogramme";
home_8 = "LAN/WLAN MAC";
home_9 = "Version du code d'amorce";
home_10 = "Adresse IP";
home_11 = "Matériel  ";
home_12 = "Masque de Sous-Réseau";
home_13 = "Serveur DHCP";
home_14 = "Paramètres Internet";
home_15 = "Caractéristiques";
home_16 = "Adresse MAC du WAN ";
home_17 = "NAT";
home_18 = "IP WAN";
home_19 = "Fonction sans fil";
home_20 = "Passerelle par défaut";	
home_21 = "SSID";	
home_22 = "Serveur DNS principal";
home_23 = "Sécurité";
home_24 = "Désactivé";
home_25 = "WEP";
home_26 = "WPA (avec serveur radius)";
home_27 = "WPA-PSK(sans serveur)";
home_28 = "Serveur DNS secondaire";
home_29 = "ADSL";
home_30 = "Language";//<=====Dave=====
home_31 = "Type";
home_32 = "Current Langugae";//<=====Dave=====
home_33 = "Statut";
home_34 = "Available Langugaes";//<=====Dave=====
home_35 = "Aucune liaison";
home_36 = "Voie descendante";
home_37 = "Voie ascendante";
home_38 = "Débit de données";
home_39 = "Marge d'immunité au bruit";
home_40 = "Puissance en sortie";
home_41 = "Atténuation";
home_42 = "Accueil Configuration";
home_43 = "Activé";
home_44 = "Désactivé";
home_45 = "English";
home_46 = "German";
home_47 = "Fran&ccedil;ais";
home_48 = "Español";
home_49 = "Paramètres de réseau local sans fil";
home_50 = "Adresse MAC du réseau sans fil local";
home_51 = "Heure";
home_52 = "WPS";

// -------------- Login ----------------
lgn_1 = "Connexion";
lgn_2 = "Avant d'apporter des modifications, vous devez vous connecter avec votre mot de passe. Si vous n'avez pas encore créé un mot de passe personnalisé, laissez ce champ vide et cliquez sur « Envoyer ».";
lgn_3 = "Mot de passe";
lgn_4 = "Par défaut ";
lgn_5 = "Effacer";
lgn_6 = "Envoyer";

// -------------- LAN Main ----------------
lm_1 = "LAN";
lm_2 = "LAN";
lm_3 = "Le serveur DHCP attribue automatiquement des adresses IP à chaque ordinateur afin de simplifier la configuration de la mise en réseau. Les paramètres par défaut du serveur DHCP sont compatibles avec la plupart des applications. Vous pouvez apporter des modifications aux paramètres si vous le désirez.";
lm_4 = "Les modifications que vous pouvez apporter sont :";
lm_5 = "Modifier l'adresse IP interne du routeur. Valeur par défaut = 192.168.2.1";
lm_6 = "Modifier le masque de sous-réseau. Le masque par défaut est 255.255.255.0";
lm_7 = "Activer/Désactiver la fonction de serveur DHCP. Par Défaut= ON (Activé)";
lm_8 = "Spécifiez l'adresse de départ et de fin de la Réserve d'Adresses IP Par défaut = Départ : 2 / Fin : 100";
lm_9 = "Entrer la durée d'autorisation de l'adresse IP Par défaut = Permanent";
lm_10 = "Entrez un Nom de Domaine local. Par défaut = Permanent";
lm_11 = "Pour apporter des modifications, cliquez sur « Paramètres du Réseau local » sur l'onglet LAN, situé à la gauche.";
lm_12 = "Le Routeur vous fournira aussi une liste de tous les clients reliés au réseau. Pour visualiser la liste, cliquez « Liste de Clients DHCP » à l'onglet LAN, à gauche.";

// -------------- LAN Settings ----------------
ls_1 = "LAN";
ls_2 = "Paramètres de réseau local";
ls_3 = "Vous pouvez ici apporter des modifications au réseau local (LAN). Pour que les modifications soient prises en compte, vous devez appuyer sur le bouton « Enregistrer les Modifications » au bas de l'écran.";
ls_4 = "Adresse IP";
ls_5 = "Plus d'infos";
ls_6 = "Masque de Sous-Réseau";
ls_7 = "Serveur DHCP ";
ls_8 = "Activé";
ls_9 = "Éteint";
ls_10 = "La fonction de serveur DHCP permet la mise en place d'un réseau en toute simplicité, en attribuant une adresse IP à chacun des ordinateurs du réseau. Il n'est pas nécessaire d'apporter des modifications ici.";
ls_11 = "Adresse de départ de la Réserve d'Adresses IP ";
ls_12 = "Adresse de fin de la Réserve d'Adresses IP ";
ls_13 = "Durée d'autorisation";
ls_14 = "Une heure";
ls_15 = "Deux heures";
ls_16 = "Demi-journée";
ls_17 = "Un jour";
ls_18 = "Deux jours";
ls_19 = "Une semaine";
ls_20 = "Deux semaines";
ls_21 = "Toujours";
ls_22 = "La durée pendant laquelle le serveur DHCP réservera l'adresse IP pour chaque ordinateur.";
ls_23 = "Nom de domaine local";
ls_24 = "optionnel";
ls_25 = "Fonction qui vous permet d'attribuer un nom à votre réseau.";
ls_26 = "Effacer les modifications";
ls_27 = "Enregistrer les modifications";
ls_28 = "L'adresse IP choisie doit être une adresse IP non-acheminable.  192.168.x.x (où x est un nombre compris entre 0 et 255.) 10.x.x.x (où x est un nombre compris entre 0 et 255) 172.y.x.x (où y est un nombre compris entre 16 et 31, et x est un chiffre est compris entre 0 et 255.)";
ls_29 = "Vous n'avez pas entré les numéros ou certains numéros entrés ne sont pas valides. Les nombres contenus dans les zones de saisie doivent être compris entre 0 et 255.";
ls_30 = "Les nombres du masque de sous-réseau que vous avez entrés sont incorrects.";
ls_31 = "L'adresse IP LAN ne peut pas figurer dans la réserve d'adresses DHCP.";
ls_32 = "L'IP de fin doit être supérieur à l'IP de départ.";
ls_33 = "Nom du domaine local non valide";
ls_34 = "Souhaitez-vous vraiment changer l'adresse IP du réseau local ?";
ls_35 = "Veuillez modifier manuellement la zone de saisie Adresse dans la barre d'état de votre navigateur et indiquer la nouvelle adresse LAN";
ls_36 = "Le Routeur sans fil redémarre. Si vous faites cette modification à partir d'un ordinateur sans fil, celui-ci peut être déconnecté du Routeur pendant un court laps de temps.";
ls_37 = "L'IP entrée n'est pas valide";

// -------------- LAN DHCP ----------------
ld_1 = "LAN";
ld_2 = "DHCP";
ld_3 = "Liste de Clients DHCP";
ld_4 = "Cette page montre l'adresse IP, le Nom d'Hôte et l'adresse MAC de chaque ordinateur relié à votre réseau. Si vous n'avez pas spécifié de nom d'hôte pour l'ordinateur, le champ Nom d'Hôte sera vide. Pour mettre à jour la liste, cliquez sur Rafraîchir.";
ld_5 = "Adresse IP";
ld_6 = "Nom d'hôte";
ld_7 = "Adresse MAC";
ld_8 = "Actualiser";

// -------------- WAN Main ----------------
wm_1 = "Internet WAN";
wm_2 = "WAN";
wm_3 = "Vous pouvez configurer votre Routeur selon les paramètres de votre FAI à l'onglet Internet WAN. Le Routeur peut pratiquement se connecter à tous les systèmes de FAI, si bien sûr vous avez configuré votre Routeur avec les paramètres appropriés à votre type de connexion. Pour configurer votre Routeur selon les paramètres de votre FAI, cliquez sur Type de Connexion à l'onglet Internet WAN, à la gauche de l'écran.";
wm_4 = "Types de Connexions prises en charge:";
wm_5 = "PPPoE";
wm_6 = "PPPoA";
wm_7 = "Dynamic/Fixed IP (1483 Bridge)";//<=====Dave=====
wm_8 = "IP fixe ";
wm_9 = "Modem seulement (Désactivation du partage de l'Internet)";

// -------------- WAN Connection ----------------
wc_1 = "WAN";
wc_2 = "Type de Connexion";
wc_3 = "Sélectionnez votre type de connexion :";
wc_4 = "PPPoE";
wc_5 = "PPPoA";
wc_6 = "Dynamic/Fixed IP (1483 Bridge)";//<=====Dave=====
wc_7 = "IP fixe (IPoA)";
wc_8 = "Modem seulement (Désactivation du partage de l'Internet)";
wc_9 = "Suivant";

// -------------- WAN DNS ----------------
wd_1 = "WAN";
wd_2 = "DNS";
wd_3 = "Si votre FAI vous a attribué une adresse DNS spécifique, entrez l'adresse dans cette fenêtre et cliquez sur « Enregistrer les Modifications ». ";
wd_4 = "Automatiquement du FAI";
wd_5 = "Adresse DNS";
wd_6 = "Adresse DNS Secondaire ";
wd_7 = "DNS = serveur de nom de domaine. Un Serveur de Nom de Domaine est un serveur que l'on retrouve sur l'Internet, et qui traduit les URL (Universal Resource Links) telles que www.belkin.com en adresses IP.";
wd_8 = "Plus d'infos";
wd_9 = "Effacer les modifications";
wd_10 = "Enregistrer les modifications";
wd_11 = "Adresse IP incorrecte. Le dernier numéro ne peut être ni 0 ni 255.";

// -------------- WAN Connection PPPoE ----------------
wcp_1 = "PPPoE / PPPoA";
wcp_2 = "PPPoE";
wcp_3 = "PPPoA";
wcp_4 = " Pour entrez vos paramètres PPPoA, entrez les informations ci-dessous et cliquez sur \"Enregistrer les Modifications\" ";
wcp_5 = " Pour entrez vos paramètres PPPoE, entrez les informations ci-dessous et cliquez sur \"Enregistrer les Modifications\" ";
wcp_6 = "Nom d'utilisateur";
wcp_7 = "Mot de passe";
wcp_8 = "Nouvelle saisie du mot de passe";
wcp_9 = "Nom de service";
wcp_10 = "VPI / VCI";
wcp_11 = "Encapsulation";
wcp_12 = "LLC";
wcp_13 = "VC/MUX";
wcp_14 = "MTU";
wcp_15 = "N'apportez aucun changement aux paramètres de MTU, à moins que votre FAI ne vous ait fourni un paramètre différent de 1432.";
wcp_16 = "Déconnecter après ";
wcp_17 = "minutes d'inactivité.";
wcp_18 = "Utiliserl'adresse IP fixe";
wcp_19 = "Veuillez entrer votre nom d'utilisateur";
wcp_20 = "Veuillez entrer votre mot de passe";
wcp_21 = "The password you entered do not match. Please enter your password and re-type the same password.";//<=====Dave=====

// -------------- WAN Connection Dynamic/Fixed IP  ----------------
wcd_1 = "Dynamic/Fixed IP (1483 Bridge)";//<=====Dave=====
wcd_2 = " L'adresse IP WAN est un adresse IP non valide.";
wcd_3 = " Le masque de sous-réseau WAN est un adresse IP non valide.";
wcd_4 = " La Route par défaut est un adresse IP non valide.";
wcd_5 = "Cliquez ici pour entrer vos paramètres de DNS.";
wcd_6 = " Utiliser la route fixe par défaut:";
wcd_7 = "Pour configurer vos paramètres d'adressage IP dynamique, entrez les informations de connexion ci-dessous et cliquez sur « Enregistrer les Modifications ».";
wcd_8 = "IP assigned by ISP";//<=====Dave=====
wcd_9 = "Oui";
wcd_10 = "No";//<=====Dave=====

// -------------- WAN Connection Static IP  ----------------
wcs_1 = "IP fixe (IPoA)";
wcs_2 = "Aucune sélection pour la passerelle par défaut.";
wcs_3 = "Veuillez entrer/valider vos paramètres d'adresse DNS à l'écran suivant.";
wcs_4 = "Pour configurer vos paramètres d'adressage IP statique, entrez les informations de connexion ci-dessous et cliquez sur « Enregistrer les Modifications ». ";
wcs_5 = "Gateway IP Address";//<=====Dave=====
wcs_6 = "Utiliser l'interface WAN:";
wcs_7 = " Adresse IP WAN";

// -------------- WAN Connection Modem  ----------------
wcm_1 = "Modem seulement (Désactivation du partage de l'Internet)";
wcm_2 = "To enter your Modem settings, type in your information below and click \"Apply changes\".";//<=====Dave=====
wcm_3 = "Activer le service Pont";

// -------------- Wireless Main  ----------------
wlm_1 = "Sans Fil";
wlm_2 = "Dans cet onglet, vous pouvez ajuster les paramètres de la section Sans Fil du Routeur.";
wlm_3 = "Canal et SSID";
wlm_4 = "Faire des ajustements au canal sans fil et au SSID (nom du réseau sans fil).";
wlm_5 = "Sécurité";
wlm_6 = "Modifiez les paramètres de sécurité, tels que les paramètres de WPA ou de WEP. ";
wlm_7 = "Utilisation comme Point d'accès";
wlm_8 = "Définissez le mode de fonctionnement du routeur sur Point d'accès. ";
wlm_9 = "Contrôle d'adresse MAC";
wlm_10 = "Dressez une liste de clients qui obtiendront ou se verront refuser l'accès au réseau sans fil.";
wlm_11 = "Easily setup and connect to a WPA-enabled 802.11 network with WPS-certified devices using either Personal Information Number(PIN) method or Push Button Configuration(PBC) method.";
wlm_12 = "Set up a list of MAC addresses that enable the interconnection of access points wirelessly.";

// -------------- Wireless Channel and SSID  ----------------
wlcs_1 = "Canal actuel   ";
wlcs_2 = "Le SSID ne peut être vide.";
wlcs_3 = "Pour apporter des modifications aux paramètres du routeur, veuillez le faire ici. Cliquez sur « Enregistrer les modifications » pour enregistrer les paramètres.";
wlcs_4 = "Canal sans fil";
wlcs_5 = "SSID";
wlcs_6 = "Mode Sans Fil ";
wlcs_7 = "802.11g onln";
wlcs_8 = "802.11g only";
wlcs_9 = "802.11b only";
wlcs_10 = "Éteint";
wlcs_11 = "Bandwidth";//<=====Dave=====
wlcs_12 = "Diffusion du SSID ";
wlcs_13 = "Mode Protégé ";
wlcs_14 = "Auto";
wlcs_15 = "WMM";
wlcs_16 = "Disable Afterburner(wireless_wifi) for selection";//<=====Dave=====
wlcs_17 = "WMM No Acknowledgement";//<=====Dave=====

// -------------- Wireless Security None  ----------------
wlsn_1 = "Mode Sécurisé";
wlsn_2 = "WPA-PSK(sans serveur)";
wlsn_3 = "WEP 128 bits";
wlsn_4 = "WEP 64 bits";
wlsn_5 = "WPA (avec serveur radius)";
wlsn_6 = "Vous pouvez configurer les paramètres de sécurité/chiffrement ici. La Sécurité devrait être activée pour assurer la sécurité maximale du réseau sans fil. Le WPA (Wireless Protected Access) présente un changement de clés dynamique et constitue la meilleure option de sécurité. Dans les environnements sans fil, là où aucun des périphériques ne prend en charge le WPA, le mode WEP (Wired Equivalent Privacy) devrait être utilisé.";

// -------------- Wireless Security WEP 64  ----------------
wlsw64_1 = "Vous n'avez pas entré tous les chiffres hexadécimaux ou certains chiffres hexadécimaux entrés ne sont pas valides. Un chiffre hex peut être un nombre de 0 à 9 ou une lettre de A à F.";
wlsw64_2 = "Cette expression mot de passe est invalide";
wlsw64_3 = "Clé 1";
wlsw64_4 = "Clé 2";
wlsw64_5 = "Clé 3 ";
wlsw64_6 = "Clé 4";
wlsw64_7 = "Impossible d'enregistrer les modifications : le sans fil est désactivé";
wlsw64_8 = " NOTE :Pour générer automatiquement des paires hexadécimales à l'aide d'une expression mot de passe, cochez la case de gauche et saisissez ici votre expression mot de passe";
wlsw64_9 = "Expression mot de passe";
wlsw64_10 = "Générer";

// -------------- Wireless Security WEP 128  ----------------
wlsw128_1 = "(paires de 13 chiffres hexadécimaux) ";

// -------------- Wireless Security WPA PSK  ----------------
wlswp_1 = "La Clé pré-partagée WPA doit comporter entre 8 et 63 caractères ASCII ou 64 nombres hexadécimaux.";
wlswp_2 = "TKIP";
wlswp_3 = "AES";
wlswp_4 = "Authentification ";
wlswp_5 = "WPA PSK";
wlswp_6 = "WPA2-PSK";
wlswp_7 = "Technique de chiffrement ";
wlswp_8 = "Clé Pré-Partagée (Pre-Shared Key - PSK)";
wlswp_9 = "WPA-PSK(sans serveur)";
wlswp_10 = "Wireless Protected Access avec clé pré-partagée (pre-shared key) : La clé est un mot de passe, sous la forme d'un mot, d'une phrase ou d'une chaîne de lettres et de chiffres. La clé doit être composée de 8 à 63 caractères, et peut inclure des espaces et des symboles, ou une clé hex 64 bits (0-F) seulement. Chaque client se connectant à un réseau doit utiliser la même clé (clé pré-partagée) ";
wlswp_11 = "Dissimuler la PSK ";
wlswp_12 = "WPA-PSK + WPA2-PSK";

// -------------- Wireless Security WPA Radius  ----------------
wlsr_1 = "Entrez la clé RADIUS.";
wlsr_2 = "Configuration WPA/WPA2-Enterprise (RADIUS)";
wlsr_3 = "Paramètres avancés - Le Wireless Protected Access utilisant un serveur pour distribuer les clés aux clients : Cette option nécessite qu'un serveur Radius soit en opération sur le réseau.";
wlsr_4 = "WPA-RADIUS";
wlsr_5 = "WPA2-RADIUS";
wlsr_6 = "Serveur Radius ";
wlsr_7 = "Port Radius ";
wlsr_8 = "Clé Radius ";
wlsr_9 = "Intervalle de ressaisie de la clé ";
wlsr_10 = "(secondes)";

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
wlap_1 = "Veuillez modifier manuellement la zone de saisie Adresse dans la barre d'état de votre navigateur et indiquer l'adresse LAN.";
wlap_2 = "Utilisation comme Point d'accès";
wlap_3 = "Activer";
wlap_4 = "Désactiver";
wlap_5 = " L'adresse IP choisie doit être une adresse IP non-acheminable. Quelques exemples d'adresses IP non-acheminable, soit 192.168.x.x (où x est un nombre compris entre 0 et 255.) 172.y.x.x (où y est un nombre compris entre 16 et 31, et x est un chiffre est compris entre 0 et 255) 10.x.x.x (où x est un nombre compris entre 0 et 255) ";
wlap_6 = "Spécifier l'adresse IP";

// -------------- Wireless MAC filter  ----------------
wlmac_1 = "Contrôle d'adresse MAC";
wlmac_2 = "Adresse MAC";
wlmac_3 = "Ajouter";

// -------------- Firewall Main  ----------------
fwm_1 = "Pare-feu";
fwm_2 = "Votre Routeur possède un pare-feu afin de protéger votre réseau contre une multitude d'attaques provenant de pirates informatiques, incluant le Ping de la Mort (Ping of Death - PoD) et l'attaque par Déni de Service (Denial of Service - DoS). Vous pouvez au besoin désactiver la fonction de pare-feu. Désactiver le pare-feu ne rendra pas votre réseau totalement vulnérable aux attaques provenant des pirates informatiques, mais il est recommandé d'activer le pare-feu aussi souvent que possible.";

// -------------- Firewall Virtual Sever  ----------------
fwvs_1 = "Serveurs Virtuels";
fwvs_2 = "Active Worlds";
fwvs_3 = "Age of Empires";
fwvs_4 = "Age of Empires Expansion: The Rise of Rome";
fwvs_5 = "Age of Empires II Expansion: The Conquerors";
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
fwvs_23 = "Close Combat pour Windows";
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
fwvs_38 = "Jeux DirectX 7";
fwvs_39 = "Jeux DirectX 8";
fwvs_40 = "Serveur de nom de domaine (DNS)";
fwvs_41 = "Doom";
fwvs_42 = "Dune 2000";
fwvs_43 = "Dwyco Video Conferencing";
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
fwvs_54 = "Serveur FTP";
fwvs_55 = "GNUtella";
fwvs_56 = "Golf Édition 2001";
fwvs_57 = "Go2Call";
fwvs_58 = "Half Life";
fwvs_59 = "Serveur Half Life";
fwvs_60 = "Serveur Heretic II";
fwvs_61 = "I76";
fwvs_62 = "Client ICUII";
fwvs_63 = "IPSEC";
fwvs_64 = "Ivisit";
fwvs_65 = "IRC";
fwvs_66 = "IStreamVideo2HP";
fwvs_67 = "KaZaA";
fwvs_68 = "Kohan Immortal Sovereigns";
fwvs_69 = "LapLink Gold";
fwvs_70 = "Links 2001";
fwvs_71 = "Serveur Lotus Notes";
fwvs_72 = "Messagerie (POP3)";
fwvs_73 = "Messagerie (SMTP)";
fwvs_74 = "MechCommander 2.0";
fwvs_75 = "MechWarrior 4";
fwvs_76 = "Media Player 7";
fwvs_77 = "Midtown Madness 2";
fwvs_78 = "Mig 29";
fwvs_79 = "Monster Truck Madness 2";
fwvs_80 = "Motocross Madness 2";
fwvs_81 = "Serveur Motorhead";
fwvs_82 = "MSN Gaming Zone";
fwvs_83 = "MSN Messenger";
fwvs_84 = "Myth";
fwvs_85 = "Serveur Myth II";
fwvs_86 = "Myth: The Fallen Lords";
fwvs_87 = "Need for Speed";
fwvs_88 = "NetMech";
fwvs_89 = "Netmeeting 2.0, 3.0, Intel Video Phone";
fwvs_90 = "Network Time Protocol (NTP)";
fwvs_91 = "Serveur de News (NNTP)";
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
fwvs_102 = "Quake II (client et serveur)";
fwvs_103 = "Quake III";
fwvs_104 = "Red Alert";
fwvs_105 = "RealAudio";
fwvs_106 = "Real Player 8 Plus";
fwvs_107 = "Rise of Rome";
fwvs_108 = "Roger Wilco";
fwvs_109 = "Rogue Spear";
fwvs_110 = "Serveur de shell sécurisé (SSH)";
fwvs_111 = "Serveur Web sécurisé (HTTPS)";
fwvs_112 = "ShoutCast";
fwvs_113 = "SNMP";
fwvs_114 = "Interruption SNMP";
fwvs_115 = "Speak Freely";
fwvs_116 = "StarCraft";
fwvs_117 = "Starfleet Command";
fwvs_118 = "StarLancer";
fwvs_119 = "SWAT3";
fwvs_120 = "Serveur Telnet";
fwvs_121 = "TFTP";
fwvs_122 = "The 4th Coming";
fwvs_123 = "Tiberian Sun: C&C III";
fwvs_124 = "Total Annihilation";
fwvs_125 = "Ultima";
fwvs_126 = "Unreal Tournament";
fwvs_127 = "Urban Assault";
fwvs_128 = "VoxPhone 3.0";
fwvs_129 = "Warbirds 2";
fwvs_130 = "Serveur Web (HTTP)";
fwvs_131 = "WebPhone 3.0";
fwvs_132 = "Westwood Online";
fwvs_133 = "Windows 2000 Terminal Server";
fwvs_134 = "X Windows";
fwvs_135 = "Yahoo Pager";
fwvs_136 = "Yahoo Messenger Chat";
fwvs_137 = "Toutes les entrées sont pleines.\nVeuillez effacer certaines entrées et recommencer.";
fwvs_138 = "Cette fonction vous permet de relayer les appels de service externes (Interner) tel un serveur Web (port 80), un serveur FTP (port 21) ou autres applications via votre Routeur vers votre réseau interne.";
fwvs_139 = "Sélectionnez un";
fwvs_140 = "Effacer";
fwvs_151 = "Type";
fwvs_152 = "Voulez-vous effacer toutes les entrées ?";
fwvs_153 = "Voulez-vous effacer l'entrée";


// -------------- Firewall Client IP filter  ----------------
fwcf_1 = "Filtres d'IP des clients";
fwcf_2 = "Dimanche";
fwcf_3 = "Lundi";
fwcf_4 = "Mardi";
fwcf_5 = "Mercredi";
fwcf_6 = "Jeudi";
fwcf_7 = "Vendredi";
fwcf_8 = "Samedi";
fwcf_9 = "L'Adresse source est une adresse IP non valide.";
fwcf_10 = "Le Port de destination est un numéro de port ou une plage non valide .";
fwcf_11 = "Le Routeur peut être configuré de sorte à limiter l'accès de certains ordinateurs à Internet, au courrier électronique ou à certains services réseau";
fwcf_12 = "Les Deux";
fwcf_13 = "Temps de blocage";
fwcf_14 = "Toujours";
fwcf_15 = "Bloquer";
fwcf_16 = "Jour";
fwcf_17 = "Heure";
fwcf_18 = "Port";

// -------------- Firewall DMZ  ----------------
fwdmz_1 = "Zone DMZ";
fwdmz_2 = "La zone DMZ vous permet de spécifier quel ordinateur de votre réseau doit être placé à l'extérieur du pare-feu NAT. Cette opération peut s'avérer nécessaire si la traduction d'adresse réseau (NAT) empêche le bon fonctionnement d'applications telles que les jeux ou les vidéoconférences. Servez-vous de cette fonction au besoin. L'ordinateur placé dans la zone DMZ ne sera pas protégé contre les attaques provenant de hackers. Pour placer un ordinateur dans la zone DMZ, entrez les derniers chiffres de son adresse IP dans le champ de saisie ci-dessous, et sélectionnez « Activer ». Cliquez « Enregistrer les Modifications  » pour que les modifications apportées soient prises en compte.";
fwdmz_3 = "Adresse IP de l'hôte DMZ virtuel";
fwdmz_4 = "IP fixe ";
fwdmz_5 = "IP privée";

// -------------- Firewall DDNS  ----------------
fwddns_1 = "Nom d'hôte vide.";
fwddns_2 = "Nom de domaine vide.";
fwddns_3 = "Nom d'utilisateur vide.";
fwddns_4 = "Courriel non valide.";
fwddns_5 = "Mot de passe vide.";
fwddns_6 = "Clé non valide.";
fwddns_7 = "DDNS";
fwddns_8 = "Les services DDNS (Dynamic DNS) vous permettent d'utiliser un nom de domaine même si votre adresse IP Internet est dynamique. Vous devez souscrire au service DDNS auprès de l'un des services DDNS énumérés.";
fwddns_9 = "Service DDNS";
fwddns_10 = "Désactiver le DDNS";
fwddns_11 = "État DDNS";
fwddns_12 = "Déconnecté";
fwddns_13 = "Connecté";
fwddns_14 = "Nom d'utilisateur";
fwddns_15 = "Mot de passe";
fwddns_16 = "Nom de Domaine";
fwddns_17 = "E-mail";
fwddns_18 = "La clé";
fwddns_19 = "Mise à jour DNS Dynamique";

// -------------- Firewall Wan Ping Blocking  ----------------
fwwpb_1 = "Blocage du ping WAN";
fwwpb_2 = "FONCTION AVANCÉE ! Vous pouvez configurer le Routeur de sorte qu'il ignore un ping ICMP (ping au port WAN). Cette fonction rehausse le niveau de sécurité.";
fwwpb_3 = "Blocage du Ping ICMP";

// -------------- Firewall Security Log  ----------------
fwsl_1 = "Journal de sécurité";
fwsl_2 = "Le routeur conserve un journal de l'activité à l'intérieur de celui-ci, telle que les connexions et déconnexions, et toute tentative de connexion au routeur en provenance de l'Internet. Vous pouvez visualiser le journal ci-dessous.";
fwsl_3 = "Journal";
fwsl_4 = "Enregistrer";
fwsl_5 = "Effacer";

// -------------- Utility Main  ----------------
utm_1 = "Utilitaires";
utm_2 = "Cet écran vous permet de gérer plusieurs paramètres du Routeur et accomplir certaines tâches administratives.";
utm_3 = " Redémarrer le Routeur ";
utm_4 = "Parfois il peut êre utile de redémarrer le routeur lorsque celui-ci fonctionne de façon inappropriée. Redémarrer le Routeur n'affectera en rien vos paramètres de configuration.";
utm_5 = "Rétablir les paramètres par défaut";
utm_6 = "Cette option rétablira les paramètres du Routeur vers les paramètres par défaut du fabricant. Nous vous recommandons de faire une copie de vos paramètres avant de rétablir la configuration par défaut.";
utm_7 = "Sauvegarder les paramètres";
utm_8 = "Vous pouvez sauvegarder votre configuration actuelle grâce à cette fonction. Cela vous permettra de la rétablir plus tard si vous perdez les paramètres ou s'ils sont modifiés. Nous vous recommandons de faire une copie de vos paramètres avant de mettre à jour le micrologiciel.";
utm_9 = "Mise à jour du micrologiciel";
utm_10 = "De temps à autre, Belkin peut lancer une nouvelle version du micrologiciel du Routeur. Ces mises à jour peuvent contenir des améliorations et des solutions aux problèmes existants.";
utm_11 = "Paramètres du système";
utm_12 = " La page \" Paramètres du système\" est l'endroit où vous pouvez entrer un nouveau mot de passe d'administrateur, régler le fuseau horaire, activer la gestion à distance, et activer/désactiver la fonction de NAT ";
utm_13 = " Rétablir les Paramètres Préalablement Sauvegardés ";
utm_14 = "Cette option vous permet de rétablir une configuration sauvegardée préalablement.";

// -------------- Utility Reset  ----------------
utrst_1 = "Voulez-vous vraiment redémarrer le Routeur ? Redémarrer le routeur n'affectera en rien votre configuration.";
utrst_2 = "Allouez jusqu'à 60 secondes au Routeur pour redémarrer. Ne débranchez pas le Routeur avant que le processus de redémarrage ne soit complété.";
utrst_3 = "Redémarrer le Routeur";
utrst_4 = "Il peut parfois être utile de redémarrer le Routeur lorsque celui-ci fonctionne de façon incongrue. Redémarrer le Routeur n'affectera en rien vos paramètres de configuration. Cliquez sur le bouton « Redémarrer le Routeur » ci-dessous pour redémarrer le Routeur. ";

// -------------- Utility Factory Default  ----------------
utfd_1 = "Rétablir les paramètres par défaut du fabricant ";
utfd_2 = "AVERTISSEMENT : Tous vos réglages seront perdus. Voulez-vous vraiment continuer ?";
utfd_3 = "La restauration des paramètres par défaut peut prendre jusqu'à 60 secondes. N'éteignez pas le routeur pendant le processus.";
utfd_4 = "Les paramètres par défaut ne seront pas restaurés. Aucun paramètre ne sera perdu !";
utfd_5 = "Cette option rétablira les paramètres du Routeur vers les paramètres par défaut du fabricant. Nous vous recommandons de faire une copie de vos paramètres avant de rétablir la configuration par défaut. Pour rétablir la configuration par défaut, cliquez sur le bouton « Rétablir les Paramètres par Défaut » ci-dessous.";
utfd_6 = "Rétablir les Paramètres par Défaut";

// -------------- Utility Save/Backup settings  ----------------
utss_1 = "Enregistrer/Sauvegarder les paramètres actuels ";
utss_2 = "Vous pouvez sauvegarder votre configuration actuelle grâce à cette fonction. Cela vous permettra de la rétablir plus tard si vous perdez les paramètres ou s'ils sont modifiés. Nous vous recommandons de faire une copie de vos paramètres avant de mettre à jour le micrologiciel.";
utss_3 = "Enregistrer";

// -------------- Utility Previous Settings  ----------------
utps_1 = "Rétablir les Paramètres Précédents ";
utps_2 = "La mise à jour des paramètres est en cours et le routeur va redémarrer. Veuillez patienter une minute.";
utps_3 = "Voulez-vous poursuivre et rétablir les paramètres ?";
utps_4 = "Suite au rétablissement des paramètres, le Routeur peut ne pas répondre aux commandes pendant une période pouvant aller jusqu'à environ une minute.\n\nCeci est normal. Ne débranchez pas votre Routeur pendant cette période.";
utps_5 = "Cette option vous permet de rétablir une configuration sauvegardée préalablement.";
utps_6 = "Rétablir";

// -------------- Utility Firmware Update  ----------------
utfu_1 = "Mise à jour du micrologiciel";
utfu_2 = "Rechercher une nouvelle version du micrologiciel";
utfu_3 = "Vérifier le micrologiciel";
utfu_4 = "Téléchargement du logiciel en cours. Veuillez patienter une minute.";
utfu_5 = "Veuillez spécifier où se trouve le fichier de mise à niveau. Entrez le nom du fichier ainsi que son chemin d'accès ou cliquez sur « Parcourir » pour accéder à l'emplacement du fichier.";
utfu_6 = "Voulez-vous vraiment poursuivre la mise à jour ?";
utfu_7 = "À la fin de la mise à niveau, il est possible que le routeur ne réponde pas aux commandes pendant une minute. Ceci est normal. Ne fermez ni ne redémarrez votre Routeur pendant cette période.";
utfu_8 = "De temps à autre, Belkin peut lancer une nouvelle version du micrologiciel du Routeur. Ces mises à jour peuvent contenir des améliorations et des solutions à des problèmes existants. Cliquez sur le lien ci-dessous pour vérifier la disponibilité d'une mise à jour du micrologiciel de ce Routeur.";
utfu_9 = "REMARQUE : Veuillez faire une copie de vos paramètres avant de mettre à jour le micrologiciel. <b><a  style=\"FONT-SIZE: 11px; color:#0066FF\" href=\"util_save.html\"> Cliquez ici </a></b> pour accéder à la page Enregistrer/Sauvegarder les paramètres en cours.";
utfu_10 = "Version du microprogramme";
utfu_11 = "Mettre à jour le micrologiciel";
utfu_12 = "Mise à Jour";
utfu_13 = "Mise à jour du micrologiciel en cours.";
utfu_14 = "N'INTERROMPEZ PAS LE PROCESSUS ET NE DÉBRANCHEZ PAS LE ROUTEUR. Ceci pourrait rendre votre Routeur inutilisable.";

// -------------- Utility System Settings  ----------------
utsys_1 = "Paramètres du système";
utsys_2 = "Dimanche";
utsys_3 = "Lundi";
utsys_4 = "Mardi";
utsys_5 = "Mercredi";
utsys_6 = "Jeudi";
utsys_7 = "Vendredi";
utsys_8 = "Samedi";
utsys_9 = "Janvier";
utsys_10 = "Février";
utsys_11 = "Mars";
utsys_12 = "Avril";
utsys_13 = "Mai";
utsys_14 = "Juin";
utsys_15 = "Juillet";
utsys_16 = "Août";
utsys_17 = "Septembre";
utsys_18 = "Octobre";
utsys_19 = "Novembre";
utsys_20 = "Décembre";
utsys_21 = "132.163.4.102-Amérique du Nord";
utsys_22 = "192.5.41.41-Amérique du Nord";
utsys_23 = "192.5.41.209-Amérique du Nord";
utsys_24 = "207.200.81.113-Amérique du Nord";
utsys_25 = "208.184.49.9-Amérique du Nord";
utsys_26 = "129.132.2.21-Europe";
utsys_27 = "130.149.17.8-Europe";
utsys_28 = "128.250.36.3-Australie";
utsys_29 = "137.189.8.174-Asie/Pacifique";
utsys_30 = "Ligne internationale de changement de date ouest";
utsys_31 = "Îles Midway, Samoa";
utsys_32 = "Hawaii";
utsys_33 = "Alaska";
utsys_34 = "Pacifique, Tijuana";
utsys_35 = "Arizona, Mazatlan";//<=====Dave=====
utsys_36 = "Chihuahua, La Paz";//<=====Dave=====
utsys_37 = "Montagnes Rocheuses";
utsys_38 = "Central America";//<=====Dave=====
utsys_39 = "Centre";
utsys_40 = "Guadalajara, Mexico City, Monterrey";//<=====Dave=====
utsys_41 = "Saskatchewan";
utsys_42 = "Bogota, Lima, Quito";
utsys_43 = "Est";
utsys_44 = "Indiana";
utsys_45 = "Heure de Atlantique";
utsys_46 = "Caracas, La Paz";
utsys_47 = "Santiago";
utsys_48 = "Terre-Neuve";
utsys_49 = "Brasilia";
utsys_50 = "Buenos Aires, Georgetown";
utsys_51 = "Groenland";
utsys_52 = "Centre-Atlantique";
utsys_53 = "Acores";
utsys_54 = "Iles du Cap-Vert";
utsys_55 = "Casablanca, Monrovia";
utsys_56 = "Heure de Greenwich Dublin, Edimbourg, Lisbonne, Londres";
utsys_57 = "Amsterdam, Berlin, Berne, Rome, Stockholm, Vienne";
utsys_58 = "Belgrade, Bratislava, Budapest, Ljubljana, Prague";
utsys_59 = "Bruxelles, Copenhague, Madrid, Paris";
utsys_60 = "Sarajevo, Skopje, Varsovie, Zagreb";
utsys_61 = "Afrique centrale et occidentale";
utsys_62 = "Athènes, Istanbul, Minsk";
utsys_63 = "Bucarest";
utsys_64 = "Le Caire";
utsys_65 = "Harare, Pretoria";
utsys_66 = "Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius";//<=====Dave=====
utsys_67 = "Jerusalem";//<=====Dave=====
utsys_68 = "Bagdad";
utsys_69 = "Koweït, Riyad";
utsys_70 = "Moscou, St. Petersbourg, Volgograd";
utsys_71 = "Nairobi";
utsys_72 = "Téhéran";
utsys_73 = "Abu Dhabi, Muscat";
utsys_74 = "Baku, Tbilisi, Yerevan";//<=====Dave=====
utsys_75 = "Kaboul";
utsys_76 = "Iekaterinbourg";
utsys_77 = "Islamabad, Karachi, Tashkent";//<=====Dave=====
utsys_78 = "Chennai, Kolkata, Mumbai, New Delhi";//<=====Dave=====
utsys_79 = "Kathmandu";//<=====Dave=====
utsys_80 = "Almaty, Novosibirsk";//<=====Dave=====
utsys_81 = "Astana, Dhaka";//<=====Dave=====
utsys_82 = "Sri Jayawardenepura";//<=====Dave=====
utsys_83 = "Rangoon";//<=====Dave=====
utsys_84 = "Bangkok, Hanoi, Jakarta";
utsys_85 = "Krasnoyarsk";//<=====Dave=====
utsys_86 = "Pekin, Chongqoing, Hong Kong, Ouroumtsi";
utsys_87 = "Irkutsk, Ulaan Bataar";//<=====Dave=====
utsys_88 = "Kuala Lumpur, Singapore";//<=====Dave=====
utsys_89 = "Perth";
utsys_90 = "Taipei";
utsys_91 = "Osaka, Sapporo, Tokyo";
utsys_92 = "Seoul";//<=====Dave=====
utsys_93 = "Yakoutsk";
utsys_94 = "Adelaide";//<=====Dave=====
utsys_95 = "Darwin";//<=====Dave=====
utsys_96 = "Brisbane";
utsys_97 = "Canberra, Melbourne, Sydney";
utsys_98 = "Guam, Port Moresby";
utsys_99 = "Hobart";
utsys_100 = "Vladivostok";
utsys_101 = "Magadan";
utsys_102 = "Solomon Is., New Caledonia";//<=====Dave=====
utsys_103 = "Auckland, Wellington";
utsys_104 = "Fidji, Kamtchatka, Iles Marshall";
utsys_105 = "Autres";
utsys_106 = "Aucun(e)";
utsys_107 = "Avant d'activer cette fonction, il est FORTEMENT RECOMMANDÉ que vous ajoutiez un mot de passe administrateur.";
utsys_108 = "Please choose the following remote management type :\n1.Any IP address can remotely manage the router\n2.Only this IP address can remotely manage the router";//<=====Dave=====
utsys_109 = "Numéro incorrect ! Doit être compris entre 1..65535";
utsys_110 = "Le premier serveur temporel est « Autre », mais le champ « Autre » est vide.";
utsys_111 = "NTP IP Address is invalid IP address.";//<=====Dave=====
utsys_112 = "Le second serveur temporel est « Autre », mais le champ « Autre » est vide.";
utsys_113 = "L'ancien mot de passe admin est incorrect.";
utsys_114 = "Password should not be less than 3 characters or lognger than 12 characters.";//<=====Dave=====
utsys_115 = "Les mots de passe ne correspondent pas.";
utsys_116 = "Login Timeout should be between 1 and 99.";//<=====Dave=====
utsys_117 = "Mot de passe Administrateur";
utsys_118 = "Le Routeur est livré SANS mot de passe défini. Si par souci de sécurité vous désirer ajouter un mot de passe, vous pouvez le configurer ici.";
utsys_119 = "Entrez le Mot de Passe actuel ";
utsys_120 = "Entrez le nouveau mot de passe ";
utsys_121 = "Confirmer le nouveau Mot de Passe ";
utsys_122 = "Temporisation de la Connexion ";
utsys_123 = "1-99 minutes";
utsys_124 = "Définition d'un fuseau horaire";
utsys_125 = "Définissez votre fuseau horaire. Si vous demeurez dans une région ayant recours à l'heure d'été, cochez cette case.";
utsys_126 = "Fuseau horaire";
utsys_127 = "Heure d'été";
utsys_128 = "Ajuster automatiquement à l'heure d'été";
utsys_129 = "Premier Serveur temps NTP";
utsys_130 = "Second Serveur temps NTP";
utsys_131 = "Gestion à distance";
utsys_132 = "FONCTION AVANCÉE ! La gestion à distance vous permet d'apporter des changements aux paramètres de votre Routeur, où que vous soyez grâce à l'Internet. Avant d'activer cette fonction, ASSUREZ-VOUS D'AVOIR ENTRÉ UN MOT DE PASSE ADMINISTRATEUR.";
utsys_133 = "Enable Remotely Management";//<=====Dave=====
utsys_134 = "N'importe quelle adresse IP peut gérer le routeur à distance.";
utsys_135 = "Seule cette adresse IP est autorisée à gérer le routeur à distance";
utsys_136 = "Port d'accès distant";
utsys_137 = "Activer la NAT";
utsys_138 = "FONCTION AVANCÉE ! Vous permet d'éteindre la fonction de traduction d'adresse réseau (NAT). Dans la plupart des cas, il est recommandé de ne PAS DÉSACTIVER cette fonctionnalité. ";
utsys_139 = "Activer/Désactiver NAT";
utsys_140 = "UPnP";
utsys_141 = "FONCTION AVANCÉE ! Vous permet de désactiver la fonction d'UPnP du Routeur.";
utsys_142 = "Activer le UPnP";
utsys_143 = "Activer la mise à jour automatique du micrologiciel";
utsys_144 = "FONCTION AVANCÉE ! Vous permet de vérifier automatiquement la disponibilité de mises à jour pour votre routeur.";
utsys_145 = " Activation/Désactivation de la mise à jour automatique du micrologiciel";

// -------------- Check New Firmware  ----------------
cnf_1 = "Vérifier le micrologiciel";
cnf_2 = " Échec de la connexion au serveur d'informations sur le micrologiciel, vérifiez la connexion WAN.";
cnf_3 = "Aucune mise à jour du micrologiciel n'est disponible pour ce routeur !";

// -------------- Help  ----------------
hlp_1 = "Aide";
hlp_2 = "HELP OF TERMS";//<=====Dave=====
hlp_3 = "haut";
hlp_4 = "Administrateur";
hlp_5 = "Un Administrateur s'acquitte des tâches d'entretien du réseau. Dans le cas précis de ce routeur, c'est la personne qui configure le routeur et apporte les changements aux paramètres.    ";
hlp_6 = "Client";
hlp_7 = "Se dit d'un ordinateur faisant partie d'un réseau et qui utilise les services du routeur, tels que le serveur DHCP automatique et le Pare-Feu.";
hlp_8 = "DHCP";
hlp_9 = "La fonction de serveur DHCP permet la mise en place d'un réseau en toute simplicité, en attribuant une adresse IP à chacun des ordinateurs du réseau. Le serveur DHCP peut être désactivé au besoin. Si vous désactivez le serveur DHCP, vous devrez entrer manuellement une adresse IP statique pour chaque ordinateur du réseau. Le pool d'adresses IP est la plage d'adresses IP mises de côté pour attribution dynamique aux ordinateurs de votre réseau. La valeur par défaut est de 2 à 100 (99 ordinateurs). Pour changer ce nombre, entrez de nouvelles adresses IP de début et de fin, puis cliquez sur \"Enregistrer les modifications\".";
hlp_10 = "Nom de domaine local";
hlp_11 = "Vous pouvez donner un nom de domaine local (nom de réseau) à votre réseau. Il n'est pas nécessaire de modifier ce paramètre, à moins qu'un besoin avancé spécifique ne vous oblige à le faire. Vous pouvez donner n'importe quel nom à votre réseau, par exemple \"MON RÉSEAU\".";
hlp_12 = "Connexion par numérotation";
hlp_13 = "Se dit d'une connexion utilisant le réseau téléphonique public";
hlp_14 = "DNS";
hlp_15 = "DNS est l'acronyme de Domain Name Server, qui se traduit par Serveur de noms de domaine. Un serveur de noms de domaine est un serveur qui se trouve sur Internet et qui traduit les adresses URL (Universal Resource Links), telles que www.belkin.com, en adresses IP. La plupart des FAI n'exigent pas que vous entriez ces informations lors de la configuration du routeur. Si vous utilisez une connexion de type IP fixe, il est possible que vous deviez entrer une adresse DNS spécifique et une adresse DNS secondaire pour assurer le bon fonctionnement de votre connexion. Si vous utilisez une connexion de type dynamique ou PPPoE, il est fort probable que vous n'ayez pas à entrer d'adresse DNS.";
hlp_16 = "Modem DSL";
hlp_17 = "DSL est l'acronyme de Digital Subscriber Line (Ligne d'abonné numérique). Un modem DSL utilise vos lignes téléphoniques existantes pour transmettre des données à haut débit.";
hlp_18 = "IP dynamique";
hlp_19 = "ne adresse IP qui est automatiquement obtenue auprès d'un serveur DHCP.";
hlp_20 = "Ethernet";
hlp_21 = "Une norme de réseaux informatiques. Les réseaux Ethernet sont connectés par des câbles et des hubs spéciaux. Ils transmettent les données jusqu'à 10 millions de bits par seconde (Mbps).";
hlp_22 = "Pare-feu";
hlp_23 = "Frontière électronique qui empêche tout utilisateur non autorisé d'accéder à certains fichiers ou ordinateurs d'un réseau.";
hlp_24 = "Micrologiciel";
hlp_25 = "Logiciel emmagasiné dans la mémoire. Programmes essentiels qui demeurent en place même lorsque le système est éteint. Les micrologiciels sont plus faciles à modifier que les matériels informatiques, mais plus permanents que les logiciels stockés sur disque.";
hlp_26 = "Adresse IP";
hlp_27 = "L' \"Adresse IP\" est l'adresse IP interne du routeur. Pour accéder à l'Interface de configuration avancée, entrez cette adresse IP dans la barre d'adresse de votre navigateur. Cette adresse peut être modifiée au besoin. Pour modifier l'adresse IP, entrez la nouvelle adresse IP et cliquez sur \"Enregistrer les modifications\". L'adresse IP choisie doit être une adresse IP non-acheminable. Quelques exemples d'adresses IP non-acheminable, soit: 192.168.x.x (où x est un nombre compris entre 0 et 255.) 172.y.x.x (où y est un nombre compris entre 16 et 31, et x est un chiffre est compris entre 0 et 255) 10.x.x.x (où x est un nombre compris entre 0 et 255)";
hlp_28 = "ISDN";
hlp_29 = "Acronyme de Integrated Services Digital Network (Réseau numérique à intégration de services). Lignes de télécommunications numériques qui peuvent transmettre à la fois de la voix et des services réseaux numériques à un débit jusqu'à 128 K et qui sont beaucoup plus rapides et fiables que les modems haut débit analogiques. Les lignes ISDN sont offertes par la plupart des opérateurs téléphoniques.";
hlp_30 = "FAI";
hlp_31 = "Acronyme de Fournisseur d'accès à Internet. Un FAI est une entreprise qui permet aux individus et aux autres entreprises de se connecter à Internet.";
hlp_32 = "Adresse de passerelle du FAI (voir FAI pour définition)";
hlp_33 = "L'adresse de passerelle du FAI est une adresse IP correspondant au routeur Internet situé chez votre fournisseur d'accès. Cette adresse n'est requise que lorsque vous utilisez un modem câble ou ADSL.";
hlp_34 = "LAN";
hlp_35 = "Acronyme de Local Area Network (réseau local). Un LAN est un groupe d'ordinateurs et de périphériques connectés entre eux dans une zone relativement restreinte (la maison ou le bureau, par exemple). Votre réseau à domicile est considéré comme un réseau local";
hlp_36 = "Adresse MAC";
hlp_37 = " MAC est l'acronyme de Media Access Control. L'adresse MAC est l'adresse matérielle du périphérique connecté à un réseau";
hlp_38 = "MTU";
hlp_39 = "Acronyme de Maximum Transmission Unit (Unité de transmission maximale). Le plus grand paquet (unité) de données pouvant être transmis sur un médium physique particulier";
hlp_40 = "NAT";
hlp_41 = "Acronyme de Network Address Translation (Traduction d'adresse réseau). Ce procédé permet à tous les ordinateurs de votre réseau domestique d'utiliser une seule adresse IP. Grâce à la technologie NAT du de votre passerelle réseau domestique HomeConnect, vous pouvez accéder à Internet depuis tous les ordinateurs de votre réseau domestique sans devoir vous procurer d'autres adresses IP auprès de votre FAI";
hlp_42 = "Port";
hlp_43 = "Une voie logique identifiée par son numéro de port unique Les applications écoutent certains ports pour repérer des informations pouvant y être liées.";
hlp_44 = "Static IP Connection";//<=====Dave=====
hlp_45 = "La connexion « IP fixe » est moins répandue que les autres types de connexion. Si c'est le cas, vous devez connaître votre adresse IP, celle de votre masque de sous-réseau ainsi que l'adresse de passerellede votre FAI. Vous pouvez obtenir ces informations auprès de votre FAI ou parmi les documents fournis par votre FAI.";
hlp_46 = "PPPoE (Mode Routage, pour plusieurs PC)";
hlp_47 = "La plupart des fournisseurs de services ADSL utilisent la connexion de type PPPoE. Si vous utilisez un modem ADSL pour vous brancher à Internet, votre FAI utilise probablement le protocole PPPoE pour vous connecter au service. Si vous disposez, chez vous ou au bureau, d'une connexion Internet qui ne nécessite pas de modem, vous pouvez également utiliser le PPPoE. Votre type de connexion est le PPPoE si: 1)Votre FAI vous a attribué un nom d'utilisateur et un mot de passe, qui sont requis pour vous brancher à Internet. 2)Votre FAI vous a fourni des logiciels tels que WinPOET et Enternet300, et vous utilisez ceux-ci pour vous brancher à Internet. 3)Vous devez double-cliquer une icône sur votre bureau, autre que celle de votre navigateur, pour vous brancher à Internet. Pour configurer le routeur selon le protocole PPPoE, entrez votre nom d'utilisateur et votre mot de passe dans les champs prévus. si votre routeur est correctement configuré. Pour de plus amples informations sur la configuration de votre routeur selon le protocole PPPoE, reportez-vous au manuel de l'utilisateur.";
hlp_48 = "PPPoA";
hlp_49 = "Point-to-Point Protocol Over ATM. Using the PPP dial-up protocol with ATM as the transport. Used by some DSL providers, IP packets travel from the PC over Ethernet to the DSL modem. The DSL modem adds the PPP protocol to the IP packets and transports them to the carrier's DSLAM via ATM.";//<=====Dave=====
hlp_50 = "Temps d'inactivité";
hlp_51 = " La fonction de déconnexion permet de déconnecter automatiquement le routeur de votre FAI lorsque celui-ci est inactif pendant une période de temps déterminée. Par exemple, en sélectionnant cette option et en entrant le chiffre 5 dans le champ des minutes, le routeur se déconnectera automatiquement d'Internet après 5 minutes d'inactivité Internet. Cette option devrait être utilisée si votre FAI vous facture à la minute.";
hlp_52 = "PPPoE (mode Routage, pour plusieurs PC)";
hlp_53 = "Désactiver le partage d'Internet (mode Pont, pour un seul PC)";
hlp_54 = "Protocole multiple sur réseau ATM (mode Routage, pour plusieurs PC)";
hlp_55 = "PPTP";
hlp_56 = "Acronyme de Point-to-Point Tunneling Protocol (Protocole de tunnelisation poste à poste). Une version améliorée du PPP qui possède la capacité d'encapsuler des paquets de données formatés pour un protocole réseau en paquets pouvant être utilisés par un autre protocole. Cette technique de tunnellisation permet aux données TCP/IP d'être transmises sur un réseau non-TCP/IP. Le PPTP peut être utilisé pour relier deux réseaux physiques différents, en utilisant l'Internet comme intermédiaire";
hlp_57 = "SNTP";
hlp_58 = "Acronyme de Simple Network Time Protocol. Norme de communication permettant la transmission d'informations en temps réel sur un réseau ou Internet";
hlp_59 = "SPI";
hlp_60 = " Acronyme de Stateful Packet Inspection. SPI est le type de sécurité Internet pour entreprises que propose votre passerelle réseau domestique HomeConnect. Grâce au SPI, la passerelle se comporte comme un pare-feu et protège votre réseau contre les pirates informatiques. ";
hlp_61 = "IP fixe ";
hlp_62 = "Une adresse IP qui est configurée manuellement et qui ne change jamais";
hlp_63 = "Masque de Sous-Réseau";
hlp_64 = "FONCTION AVANCÉE ! Il n'est pas nécessaire de modifier le masque de sous-réseau. Il est toutefois possible de le modifier au besoin. N'apportez des changements au masque de sous-réseau que si vous le devez absolument";
hlp_65 = "TCP";
hlp_66 = "Acronyme de Transmission Control Protocol. Protocole de transport de données le plus courant sur Internet. Le protocole TCP est orienté vers la connexion et la transmission, et procure une communication fiable entre les réseaux à commutation de paquets.";
hlp_67 = "TCP/IP";
hlp_68 = "Acronyme de Transmission Control Protocol over Internet Protocol. Il s'agit du protocole standard pour la transmission des données sur Internet.";
hlp_69 = "UDP";
hlp_70 = "Acronyme de User Datagram Protocol. Protocole de communication pour la couche réseau Internet, la couche de transport et la couche session, ce qui rend possible l'envoi d'un message datagramme depuis un ordinateur vers une application fonctionnant sur un autre ordinateur. Contrairement au TCP, l'UDP ne requiert pas de connexion et ne garantit pas une communication fiable ; l'application elle-même doit traiter les erreurs et vérifier la fiabilité de la transmission.";
hlp_71 = "WAN";
hlp_72 = "Acronyme de Wide Area Network (réseau étendu). Réseau qui permet de connecter des ordinateurs situés dans des zones géographiquement distinctes (bâtiments, villes ou pays différents). Internet est un réseau étendu.";
hlp_73 = "Adresse IP WAN";
hlp_74 = "L'adresse IP que le FAI attribue au routeur.";
hlp_75 = "Canal et SSID";
hlp_76 = "Pour modifier le canal d'opération du routeur, sélectionnez le canal désiré à partir de la liste déroulante et sélectionnez votre canal. Cliquez \"Enregistrer les modifications\" pour enregistrer les paramètres. Vous pouvez également modifier le SSID. Le SSID est l'équivalent du nom du réseau sans fil. Vous pouvez lui donner n'importe quel nom. S'il existe d'autres réseaux sans fil dans votre environnement immédiat, vous devez donner un nom unique au vôtre. Pour modifier le SSID, cliquez sur la zone SSID, puis entrez le nouveau nom. Cliquez \"Enregistrer les modifications\" pour faire la modification.";
hlp_77 = "Utilisation de la fonction de commutation entre les modes sans fil";
hlp_78 = "1) 802.11g &amp; 802.11b : Setting the Router to this mode will let 802.11g-, and 802.11b-compliant devices to join the network. 2) Off : This mode will turn OFF the Router's access point, so no wireless devices can join the network. Turning off the wireless function of your Router is a great way to secure your network when you are away from home for a long period of time, or don't want to use the wireless feature of the Router at a certain time.";//<=====Dave=====
hlp_79 = "Diffusion du SSID ";
hlp_80 = "Une des caractéristiques des réseaux sans fil est la possibilité pour un adaptateur réseau sans fil d'un ordinateur de rechercher automatiquement un réseau sans fil existant. Ceci est rendu possible en paramétrant la carte à TOUT Votre routeur est en mesure de bloquer cette recherche aélatoire d'un réseau. Si vous désactivez la , le seul moyen dont dispose votre ordinateur pour se connecter au réseau est de paramétrer le SSID de celui-ci en lui donnant le nom du réseau (par exemple WLAN). Assurez-vous de connaître le SSID (nom du réseau) avant d'activer cette fonction. Il est possible de rendre presque invisible votre réseau sans fil. En désactivant l'émission du SSID, votre réseau n'apparaîtra pas lors de l'analyse du site. L'analyse de site est une fonction que possèdent la majorité des adaptateurs réseau sans fil disponibles sur le marché. Il balaye l' air ambiant à la recherche de réseaux et permet à l'ordinateur de choisir parmi eux. Le fait de désactiver la fonction de diffusion du SSID renforce la sécurité du réseau.";
hlp_81 = "Utilisation comme Point d'accès";
hlp_82 = "Lorsque vous utilisez le routeur comme point d'accès, vous devez indiquer l'adresse IP du point  d'accès. Cette adresse IP doit figurer dans la même plage que le réseau auquel vous allez vous connecter. Pour accéder à nouveau à l'interface d'installation évoluée du routeur, entrez l'adresse IP dans le navigateur Web et connectez-vous.";
hlp_83 = "Sans Fil Contrôle de l'Adresse MAC";
hlp_84 = "Le filtre d'adresse MAC représente une puissante caractéristique de sécurité, vous permettant d'autoriser, à des ordinateurs spécifiques, l'accès à votre réseau sans fil. Remarque : Cette liste ne s'applique qu'aux ordinateurs sans fil. Cette liste peut être configurée de sorte que tout ordinateur non spécifié dans les paramètres du filtre et qui tente d'accéder au réseau se verra refuser l'accès. Lorsque vous activez cette fonction, vous devez entrer l'adresse MAC de chaque client (ordinateur) de votre réseau, pour permettre à chacun d'accéder au réseau. La fonction « Bloquer » vous permet d'activer et de désactiver facilement l'accès au réseau pour tout ordinateur sans devoir ajouter l'adresse MAC de l'ordinateur à la liste ni la supprimer.<Br>Dresser une liste d'ordinateurs « autorisés » <Br>1.Sélectionnez la case d'option « Autoriser » (1) pour commencer à dresser une liste d'ordinateurs pouvant se connecter à votre réseau sans fil. <Br>2. Puis, dans le champ « Addresse MAC » vide (3), entrez l'adresse MAC de l'ordinateur à qui vous autorisez l'accès à votre réseau sans fil. Cliquez ensuite sur « Ajouter » (4). <Br>3. Recommencez pour chaque ordinateur. <Br>4. Cliquez sur « Enregistrer les modifications » (5) pour terminer.<br><br>Dresser une liste d'ordinateurs « refusés » <Br>La liste d'accès restreint vous permet de spécifier les ordinateurs qui se verront REFUSER l'accès au réseau. Tout ordinateur se trouvant dans la liste se verra refuser l'accès au réseau sans fil. Tous les autres pourront y accéder. <Br>1.Sélectionnez la case d'option « Refuser » (2) pour commencer à dresser une liste d'ordinateurs qui se verront refuser l'accès à votre réseau sans fil. <Br>2. Puis, dans le champ « Addresse MAC » vide (3), entrez l'adresse MAC de l'ordinateur à qui vous refusez l'accès à votre réseau sans fil. Cliquez ensuite sur « Ajouter » (4). <Br>3. Recommencez pour chaque ordinateur. <Br>4. Cliquez sur « Enregistrer les modifications » (5) pour terminer."; 
hlp_85 = "Mode ACK";
hlp_86 = "Il existe deux modes d'accusés de réception (AR - ACK en anglais), pouvant être utilisés pour tirer les meilleures performances multimédia de votre réseau : Burst ACK et Immediate ACK. Immediate ACK est le paramètre par défaut. Nous vous le recommandons pour le fonctionnement normal du réseau. Modifier le Mode AR de « Immediate ACK » à « Burst ACK » peut affecter le débit à longue portée. Utilisez « Immediate ACK » lorsque la performance à grande distance est importante. Le Mode « Burst ACK » diminue le surdébit en n'acquittant pas chaque paquet envoyé sur le réseau. En présence d'une bonne connexion entre le routeur et le client, le mode « Burst ACK » peut améliorer le débit. Si une application, telle que le téléchargement de contenu vidéo en temps réel, requiert une bande passante maximale, utilisez le mode « Burst ACK ». Rappelez-vous que la performance à grande portée sera affectée par l'utilisation du mode « Burst ACK ».";
hlp_87 = "Configuration du QoS (Quality of Service)";
hlp_88 = "Le QoS s'assure que les données prioritaires sur votre réseau, telles que le contenu multimédia et la Voix sur IP (VoIP), ne soient pas « contaminées » par les données transmises sur votre réseau. Basé sur la norme 802.11e, vous pouvez activer/désactiver cette fonction ou vous pouvez choisir le mode d'accusé de réception de votre choix. Si vous comptez utiliser le transfert multimédia en temps réel ou la Voix sur IP sur votre réseau, il est recommandé d'activer la fonction QoS.";
hlp_89 = "Chiffrement";
hlp_90 = "Using Encryption can help secure your wireless network. Only one type of security may be selected at a time. Therefore the customer must select a mode that is supported on all network devices on the wireless network. This Belkin product has 5 possible Security settings: 1) Disabled. No encryption is enabled in this mode. Open networks where all users are welcome sometimes prefer to not enable encryption. 2) WPA PSK - Home (no server). WPA (Wireless protected Access) PSK is a recent standards-based security technique where each packet of information is encrypted with a different code, or key. Since the key is constantly changing, WPA is very secure. There are two types of WPA, WPA-PSK (Pre-Shared Key), and WPA-Radius Server. Obviously the difference being that one requires a server and one does not. WPA-PSK is for home and small business users who do not have a server. The PSK encryption key is generated automatically from a string of characters or Pass Phrase. Obviously the biggest security risk in WPA PSK is if someone finds out your Pass Phrase. a. TKIP verses AES. WPA setup requires the user to select whether to encrypt using TKIP or AES. The WPA standard specifies TKIP, so that is the default. Additionally TKIP should provide better compatibility between wireless products from different vendors since many wireless products will never be upgraded to AES. AES is a new encryption technique based on the un-ratified 802.11i standard. New WPA standards are being considered using AES. Although AES is not as popular, some users may prefer to use this technique. Either way, all networks devices must use the same technique. b. Pre-Shared Key. Enter any word or phrase up to 40 characters. The same PSK must also be used for every other wireless network device on the network. Watch out for upper and lower case differences (\"n\" is different than \"N\".) Remember, the easiest way to break your security is for someone to guess your PSK. 3) 128-bit WEP. Until recently, 128-bit WEP (Wired Equivalent Privacy) was the standard for wireless encryption. If not all of your wireless devices support WPA, 128bit WEP still offers very good security option. It will require you to enter hex numbers, or you can generate them automatically. 4) 64-bit WEP. Belkin only recommends 64-bit mode on networks where some devices do not support either WPA or 128bit WEP. 5) WPA - Radius Server. (This mode is accessed from the Advanced Button). WPA server is only for networks using a Radius Server. All parameter for this mode should be obtained from the administrator of your Radius Server. Unlike WPA PSK, WPA server passes the key from the server to the clients instead of generating it automatically.";//<=====Dave=====
hlp_91 = "Serveurs Virtuels";
hlp_92 = "Cette fonction vous permet d'acheminer, via le routeur et vers votre réseau interne, les appels externes (Internet) de services tels qu'un serveur web (port 80), un serveur FTP (port 21) ou d'autres applications. Parce que vos ordinateurs internes sont protégés par le pare-feu, les machines provenant de l'Internet ne peuvent accédez à ceux-ci puisqu'ils sont « invisibles ». Si vous devez configurer la fonction de Serveur virtuel pour une application particulière, vous devez contacter le fabricant de votre application et déterminer quels paramètres de ports sont nécessaires. Pour saisir manuellement les paramètres, entrez l'adresse IP dans le champ fourni pour la machine (serveur) interne, le type de port (TCP ou UDP), sélectionnez les ports publics du LAN qui doivent être passés, sélectionner « Enable [Activer] » et cliquez sur Établir Vous pouvez seulement faire passer un seul port par adresse IP interne. L'ouverture des ports de votre pare-feu risque de compromettre la sécurité de votre réseau. Vous pouvez facilement activer ou désactiver cette fonction. Il est recommandé de désactiver cette fonction lorsque vous n'utilisez pas une application spécifique.";
hlp_93 = "Utilisation du serveur DNS dynamique";
hlp_94 = "Le service DNS Dynamique vous permet d'attribuer une adresse IP dynamique à un nom d'hôte fixe parmi ceux offerts par DynDNS.org, ce qui vous permet d'accéder à vos ordinateurs à partir de maints endroits sur Internet. DynDNS.org offre ce service à la communauté des Internautes, gratuitement, pour jusqu'à cinq noms d'hôte.<br><br>Le service DNS Dynamique est idéal pour les sites web maison, les serveurs de fichiers, ou pour vous faciliter l'accès à votre PC ou aux fichiers stockés sur votre PC lorsque vous êtes au travail. Le service garantit que votre nom d'hôte pointe toujours vers votre adresse IP, peut importe si votre FAI modifie celle-ci. Lorsque votre adresse IP change, vos amis et associés peuvent toujours vous retrouver en visitant votrenom.dyndns.org !<Br><br>Inscrivez-vous gratuitement et obtenez votre nom d'hôte DNS Dynamique à http://www.dyndns.org.<Br><br><b>Configuration du client DNS Dynamique du routeur</b><br><br>Inscrivez-vous gratuitement et obtenez votre nom d'hôte DNS Dynamique à http://www.dyndns.org.<br><br><b>Configuration du client DNS Dynamique du routeur</b><br>Vous devez vous inscrire au service gratuit de mise à jour de DynDNS.org avant d'utiliser cette fonction. Après vous être inscrit, veuillez suivre les étapes ci-dessous.<br>1.Entrez votre nom d'utilisateur DynDNS.org dans le champ « User Name [Nom d'utilisateur] » (1).<br>2.Entrez votre mot de passe DynDNS.org dans le champ « Password [Mot de passe] » (2).<br>3.Entrez votre nom d'utilisateur DynDNS.org dans le champ « User Name [Nom d'utilisateur] » (3).<Br>4.Cliquez sur « Update Dynamic DNS [Mise à jour DNS Dynamique] » pour mettre à jour votre adresse IP.<Br>Lorsque votre FAI modifie l'adresse IP qui vous est attribuée, le routeur s'occupe de la mise à jour des serveurs DynDNS.org, avec votre nouvelle adresse IP. Vous pouvez également le faire manuellement, en cliquant sur le bouton « Update Dynamic DNS [Mise à jour DNS Dynamique] » (4)."; 
hlp_95 = "Filtres d'IP des clients";
hlp_96 = " Le Routeur peut être configuré de sorte à limiter l'accès de certains ordinateurs à Internet, au courrier électronique et autres fonctions réseaux, à des jours et des heures donnés. La restriction peut s'appliquer à un seul ordinateur, à un groupe d'ordinateurs ou à plusieurs ordinateurs. Par exemple, pour limiter l'accès à Internet à un ordinateur particulier, entrez l'adresse IP de l'ordinateur dont vous désirez contrôler l'accès dans les champs IP. Ensuite, entrez 80 et 80 dans les champs de ports. Sélectionnez TCP. Sélectionnez Bloquer. Vous pouvez aussi sélectionner Toujours pour bloquer l'accès en tout temps. Sélectionnez le jour du début en haut, l'heure du début en haut, le jour de fin en bas. Cliquez sur « Enregistrer les Modifications ». L'ordinateur à l'adresse IP que vous avez spécifiée ne pourra dorénavant plus accéder à l'Internet aux heures spécifiées. Remarque : Assurez-vous d'avoir sélectionné le fuseau horaire approprié sous Utilitaires > Paramètres du Système > Fuseau Horaire.";
hlp_97 = "Filtrage des adresses MAC";
hlp_98 = "The MAC Address Filter is a powerful security feature that allows you to specify which computers are allowed on the network. Any computer attempting to access the network that is not specified in the filter list will be denied access. When you enable this feature, you must enter the MAC address of each client on your network to allow network access to each or copy the MAC address by selecting the name of the computer from the \"DHCP Client List\". To enable this feature, select \"Enable\". Next, click \"Apply Changes\" to save the settings.";//<=====Dave=====
hlp_99 = "Zone DMZ";
hlp_100 = "If you have a client PC that cannot run an Internet application properly from behind the firewall, you can open the client up to unrestricted two-way Internet access. This may be necessary if the NAT feature is causing problems with an application such as a game or video conferencing application. Use this feature on a temporary basis. The computer in the DMZ is not protected from hacker attacks. To put a computer in the DMZ, enter the last digits of its LAN IP address in the Static IP field and click \"Apply Changes\" for the change to take effect.";//<=====Dave=====
hlp_101 = "Mot de passe Administrateur";
hlp_102 = " Le routeur est livré SANS mot de passe défini. Si par souci de sécurité vous désirer ajouter un mot de passe, vous pouvez le configurer ici. Conservez votre mot de passe dans un endroit sûr puisque vous en aurez besoin lorsque vous voudrez vous connecter au routeur par la suite. Nous recommandons aussi l'ajout d'un mot de passe si vous prévoyez utiliser la fonction de gestion à distance du routeur. L'option de temporisation de la connexion vous permet de déterminer la plage horaire pendant laquelle vous pouvez être connecté au niveau de l'interface de configuration avancée du routeur. La temporisation débute lorsqu'il n'y a plus d'activité. Par exemple, vous avez apporté des modifications au niveau de l'interface de configuration évoluée, puis vous avez quitté l'ordinateur sans cliquer sur \"Déconnexion\". En supposant que vous ayez paramétré la temporisation à 10 minutes, votre connexion prendra fin 10 minutes après votre départ. Vous devrez de nouveau vous connecter au routeur pour procéder à d'autres modifications. L'option de temporisation de la connexion sert à des fins de sécurité. La valeur par défaut est 10 minutes. Prenez note qu'un seul ordinateur à la fois peut être connecté à l'interface de configuration avancée du routeur.";
hlp_103 = "Activer la NAT";
hlp_104 = "Avant d'activer cette fonction, ASSUREZ-VOUS D'AVOIR AJOUTÉ UN MOT DE PASSE ADMINISTRATEUR. La traduction d'adresses réseau (Network Address Translation, NAT) est la méthode qui permet au routeur de partager une seule adresse IP attribuée par le FAI avec les autres ordinateurs du réseau. Cette fonction ne devrait être utilisée que par des utilisateurs avancés. Cette fonction ne devrait être utilisée que si votre FAI vous attribué de multiples adresses IP, ou vous devrez désactiver la NAT pour accéder aux configurations avancées du système.  Si vous disposez d'une seule adresse IP et si vous désactivez le NAT, les ordinateurs de votre réseau ne pourront pas accéder à Internet. D'autres problèmes peuvent aussi survenir. La désactivation NAT désactive les fonctions de votre pare-feu.";
hlp_105 = "UPnP";
hlp_106 = "L'UPnP (Universal Plug-and-Play) est une technologie qui offre un fonctionnement transparent de la messagerie vocale et vidéo, des jeux, et d'autres applications compatibles avec l'UPnP. Certaines applications nécessitent que le pare-feu du routeur soit configuré selon certains paramètres pour fonctionner correctement. Pour ce faire, vous devez habituellement ouvrir des ports TCP et UDP, et parfois même configurer des ports de déclenchement. Une application qui est compatible avec l'UPnP possède la capacité de communiquer avec le routeur, lui indiquant la manière dont le pare-feu doit être configuré. Le routeur est livré avec la fonction UPnP désactivée. Si vous utilisez une application qui est compatible avec l'UPnP, et si vous désirez bénéficier des avantages de l'UPnP, vous pouvez activer la fonction UPnP. Sélectionnez simplement l'option \"Activer\" dans la section \" Activation de l'UPnP\" dans la page Utilitaires. Cliquez sur \"Appliquer les modifications\" pour enregistrer les modifications. ";
hlp_107 = "Notification automatique de mise à jour du microprogramme";
hlp_108 = " Le Routeur possède la capacité intrinsèque de vérifier automatiquement s'il existe une nouvelle version du microprogramme et vous avertit lorsque la nouvelle version est disponible. Lorsque vous vous connectez à l'interface avancée du routeur, le routeur procédera à la recherche d'une nouvelle version du micrologiciel, si celle-ci est disponible. Vous serez averti lorsqu'une une nouvelle version du micrologiciel est disponible. Vous pouvez choisir de télécharger cette nouvelle version ou de l'ignorer. Le routeur est livré avec cette fonction désactivée. Si vous voulez l'activer, sélectionnez \"Activer\" et cliquez sur \"Enregistrer les Modifications\".";
hlp_109 = "Gestion à distance";
hlp_110 = "La gestion à distance vous permet d'apporter des changements aux paramètres du routeur où que vous soyez sur Internet. Il existe deux méthodes pour gérer votre routeur à distance. La première méthode consiste à permettre l'accès au routeur à partir de l'Internet en sélectionnant \"N'importe quelle adresse IP peut gérer le routeur à distance\". Lorsque vous aurez entré votre adresse IP WAN depuis un ordinateur sur Internet, un écran de connexion apparaîtra. Vous devrez y entrer le mot de passe du routeur. La deuxième méthode consiste à permettre à une adresse IP spécifique de gérer le routeur à distance. Cette méthode est la plus sécuritaire, mais la moins pratique. Pour y avoir recours, entrez l'adresse IP autorisée à accéder au routeur dans le champ fourni à cet effet, puis sélectionnez \"Seule cette adresse IP est autorisée à gérer le routeur à distance\". Avant d'activer cette fonction, nous vous CONSEILLONS VIVEMENT de définir un mot de passe d'administrateur. Si vous laissez le mot de passe vide, vous autorisez potentiellement des intrusions sur le routeur.";
hlp_111 = "WLAN";
hlp_112 = "Acronyme de Wireless Local Area Network (réseau local sans fil). Réseau local qui relie des ordinateurs proches entre eux via des ondes radio (comme 802.11b)";
hlp_113 = "Blocage du Ping ICMP";
hlp_114 = " Les pirates informatiques utilisent une technique appelée Pinging pour dénicher sur Internet. En émettant un ping sur une certaine adresse IP et en recevant une réponse de celle-ci, un pirate peut savoir qu'il a un poste à pirater. Lpouvez configurer le routeur de sorte qu'il ignore un ping ICMP venant de l'extérieur. Ceci rehausse le niveau de sécurité de votre routeur. Pour désactiver la réponse au ping, sélectionnez \"Blocage du ping ICMP\" et cliquez sur \"Enregistrer les modifications\". Le routeur ignorera un ping ICMP. ";
hlp_115 = "Mode Protégé ";
hlp_116 = " NOTE : Dans la majorité des cas, vous obtiendrez de meilleures performances (débit) avec le Mode Protégé étant Désactivé. Si vous travaillez dans un environnement avec un trafic 802.11b TRÈS DENSE ou subissez des interférences, vous obtiendrez de meilleures performances avec le Mode Protégé étant Activé.";
hlp_117 = "Définition d'un fuseau horaire";
hlp_118 = " Le routeur harmonise le temps en se connectant à un serveur SNTP (Simple Network Time Protocol). Ceci lui permet de synchroniser  l'horloge du système avec l'Internet planétaire. Lhorloge ainsi synchronisée est utilisée par le routeur pour garder un journal de connexions et pour contrôler le filtrage des clients. Sélectionnez le fuseau horaire du pays dans lequel vous résidez. Si vous résidez dans une région qui applique l'horaire d'été, cochez la case en regard de l'option \"Appliquer les horaires d'été \".L'horloge du système peut ne pas être mise à jour immédiatement. Laissez au moins 15 minutes au routeur pour contacter les serveurs sur Internet et recevoir une réponse. Vous ne pouvez pas modifier l'horloge vous-même. ";
hlp_119 = "Wi-Fi Multimedia (WMM)";
hlp_120 = "This feature enables the Quality of Service (QoS) function that is used for multimedia applications, such as Voice-over-IP (VoIP) and video. This allows the network packets of the multimedia application to have priority over regular data network packets, allowing multimedia applications to run smoother and with fewer errors.";
hlp_121 = "WMM No-Acknowledgement";
hlp_122 = "No-Acknowledgement refers to the acknowledge policy used at the MAC level. Enabling no-acknowledgement can result in more efficient throughput but higher error rates in a noisy Radio Frequency (RF) environment.";

// -- Restore factory defaults Successfully --
utfrds_1 = "Restauration des paramètres par défaut du constructeur réussie";
utfrds_2 = "Veuillez attendre que le témoin d'alimentation cesse de clignoter.";

// -- Reset Successfully --
utrs_1 ="Initialisation Réussie";
utrs_2 ="Veuillez attendre que le témoin d'alimentation cesse de clignoter.";
utrs_3 ="Le Routeur redémarre";
utrs_4 ="secondes restantes.";


// -- Restored Settings Successfully --
utrss_1 ="Rétablissement des paramètres réussi";
utrss_2 ="Veuillez attendre que le témoin d'alimentation cesse de clignoter.";

// -- Apply -
apply_1 = " Enregistrement des modifications ";
apply_2 = " Enregistrement des modifications. Veuillez patienter....... ";


}
