function dw(message)
{
	document.write(message);	
}

function assign_var()
{
// -------------- Menu ----------------
menu_1 = "Home";
menu_2 = "Help";
menu_3 = "Login";
menu_4 = "Logout";
menu_5 = "Internet Status";
menu_6 = "Connected";
menu_7 = "No Connection";
menu_8 = "LAN Setup";
menu_9 = "LAN Settings";
menu_10 = "DHCP Client List";
menu_11 = "Internet WAN";
menu_12 = "Connection Type";
menu_13 = "DNS";
menu_14 = "Wireless";
menu_15 = "Channel and SSID";
menu_16 = "Security";
menu_17 = "Use as Access Point";
menu_18 = "MAC Address Control";
menu_19 = "Firewall";
menu_20 = "Virtual Servers";
menu_21 = "Client IP Filters";
menu_22 = "DMZ";
menu_23 = "DDNS";
menu_24 = "WAN Ping Blocking";
menu_25 = "Security Log";
menu_26 = "Utilities";
menu_27 = "Restart Router";
menu_28 = "Restore Factory Default";
menu_29 = "Save/Backup Settings";
menu_30 = "Restore Previous Settings";
menu_31 = "Firmware Update";
menu_32 = "System Settings";
menu_33 = "Wi-Fi Protected Setup";
menu_34 = "Wireless Bridge";
		
// -------------- Home ----------------
home_1 = "Status";	
home_2 = "You will need to log in before you can change any settings";
home_3 = "Connect";
home_4 = "Disconnect";
home_5 = "Version Info";
home_6 = "LAN Settings";
home_7 = "Firmware Version";
home_8 = "LAN MAC Address";
home_9 = "Boot Code Version";
home_10 = "IP Address";
home_11 = "Hardware";
home_12 = "Subnet Mask";
home_13 = "DHCP Server";
home_14 = "Internet Settings";
home_15 = "Features";
home_16 = "WAN MAC Address";
home_17 = "NAT";
home_18 = "WAN IP";
home_19 = "Wireless Function";
home_20 = "Default Gateway";	
home_21 = "SSID";	
home_22 = "Primary DNS Server";
home_23 = "Security";
home_24 = "Disabled";
home_25 = "WEP";
home_26 = "WPA(with Radius Server)";
home_27 = "WPA-PSK(no server)";
home_28 = "Secondary DNS Server";
home_29 = "ADSL";
home_30 = "Language";
home_31 = "Type";
home_32 = "Current Langugae";
home_33 = "Status";
home_34 = "Available Langugaes";
home_35 = "Link Down";
home_36 = "Downstream";
home_37 = "Upstream";
home_38 = "Data Rate";
home_39 = "Noise margin";
home_40 = "Output power";
home_41 = "Attenuation";
home_42 = "Setup Home";
home_43 = "Enabled";
home_44 = "Disabled";
home_45 = "English";
home_46 = "German";
home_47 = "Fran&ccedil;ais";
home_48 = "Español";
home_49 = "WLAN Settings";
home_50 = "WLAN MAC Address";
home_51 = "Time";
home_52 = "WPS";

// -------------- Login ----------------
lgn_1 = "Login";
lgn_2 = "Before you can change any settings, you need to log in with a password. If you have not yet set a custom password, then leave this field blank and click \"Submit\".";
lgn_3 = "Password";
lgn_4 = "Default = leave blank";
lgn_5 = "Clear";
lgn_6 = "Submit";

// -------------- LAN Main ----------------
lm_1 = "LAN";
lm_2 = "LAN";
lm_3 = "Your Router is equipped with a DHCP server that will automatically assign IP addresses to each computer on your network. The factory default settings for the DHCP server will work in most any application. If you need to make changes to the settings, you can do so.";
lm_4 = "The changes that you can make are:";
lm_5 = "Change the Internal IP address of the Router. The default = 192.168.2.1";
lm_6 = "Change the Subnet Mask. The default = 255.255.255.0";
lm_7 = "Enable/Disable the DHCP Server Function. Default= ON (Enabled)";
lm_8 = "Specify the Starting and Ending IP Pool Address. Default = Starting: 2 / Ending: 100";
lm_9 = "Specify the IP address Lease Time. Default= Forever";
lm_10 = "Specify a local Domain Name. Default = Belkin";
lm_11 = "To make changes, click \"LAN Settings\" on the LAN tab to the left.";
lm_12 = "The Router will also provide you with a list of all client computers connected to the network. To view the list, click \"DHCP client list\" on the LAN tab to the left.";

// -------------- LAN Settings ----------------
ls_1 = "LAN";
ls_2 = "LAN Settings";
ls_3 = "You can make changes to the Local Area Network (LAN) here. For changes to take effect,you must press the \"Apply Changes\" button at the bottom of the screen.";
ls_4 = "IP Address";
ls_5 = "More Info";
ls_6 = "Subnet Mask";
ls_7 = "DHCP server";
ls_8 = "On";
ls_9 = "Off";
ls_10 = "The DHCP server function makes setting up a network very easy by assigning IP addresses to each computer on the network. It is not necessary to make any changes here.";
ls_11 = "IP Pooling Starting Address";
ls_12 = "IP Pooling Ending Address";
ls_13 = "Lease Time";
ls_14 = "One Hour";
ls_15 = "Two Hours";
ls_16 = "Half Day";
ls_17 = "One Day";
ls_18 = "Two Days";
ls_19 = "One Week";
ls_20 = "Two Weeks";
ls_21 = "Forever";
ls_22 = "The length of time the DHCP server will reserve the IP address for each computer.";
ls_23 = "Local Domain Name";
ls_24 = "optional";
ls_25 = "A feature that lets you assign a name to your network.";
ls_26 = "Clear Changes";
ls_27 = "Apply Changes";
ls_28 = "The IP address you choose should be a non-routable IP.\n  192.168.x.x (where x is anything between 0 and 255.) \n10.x.x.x (where x is anything between 0 and 255.)\n172.y.x.x (where y is anything from 16 to 31, and x is anything between 0 and 255.)";
ls_29 = "Either you have not entered all of the numbers  or some of the numbers you entered are invalid. The number in each entry box should be between 0 and 255.";
ls_30 = "The Subnet mask number you entered is invalid.";
ls_31 = "The LAN IP address can not be in the DHCP address pool.";
ls_32 = "The ending IP address must be larger than the starting IP address.";
ls_33 = "Invalid Local Domain Name";
ls_34 = "Do you really wish to change the LAN IP address?";
ls_35 = "Please change the Address entry box in the status bar of your browser manually to the new lan address";
ls_36 = "The wireless will restart, if you are making this change from wireless computer, your wireless computer maybe temperorily disconnected from the router.";
ls_37 = "The IP that you entered is invalid";

// -------------- LAN DHCP ----------------
ld_1 = "LAN";
ld_2 = "DHCP";
ld_3 = "DHCP Client List";
ld_4 = "This page shows you the IP address, Host Name and MAC address of each computer that is connected to your network. If the computer does not have a host name specified, then the Host Name field will be blank. Pressing \"Refresh\" will update the list.";
ld_5 = "IP Address";
ld_6 = "Hostname";
ld_7 = "MAC Address";
ld_8 = "Refresh";

// -------------- WAN Main ----------------
wm_1 = "Internet WAN";
wm_2 = "WAN";
wm_3 = "The Internet WAN Tab is where you will set up your Router to connect to your Internet Service Provider. The Router is capable of connecting to virtually any Internet Service Provider\'s system provided that you have correctly configured the Router\'s settings for your ISP\'s connection type. To configure the Router to connect to your ISP, click on \"Connection type\" on the Internet/WAN Tab on the left of the screen.";
wm_4 = "Connection types supported:";
wm_5 = "PPPoE";
wm_6 = "PPPoA";
wm_7 = "Dynamic/Fixed IP (1483 Bridge)";
wm_8 = "Static IP";
wm_9 = "Modem only (Disable Internet sharing)";

// -------------- WAN Connection ----------------
wc_1 = "WAN";
wc_2 = "Conection Type";
wc_3 = "Select your connection type:";
wc_4 = "PPPoE";
wc_5 = "PPPoA";
wc_6 = "Dynamic/Fixed IP (1483 Bridge)";
wc_7 = "Static IP (IPoA)";
wc_8 = "Modem only (Disable Internet sharing)";
wc_9 = "Next";

// -------------- WAN DNS ----------------
wd_1 = "WAN";
wd_2 = "DNS";
wd_3 = "If your ISP provided you with a specific DNS address to use, enter the address in this window and click \"Apply Changes\".";
wd_4 = "Automatic from ISP";
wd_5 = "DNS Address";
wd_6 = "Secondary DNS Address";
wd_7 = "DNS = Domain Name Server. A server located on the Internet that translates URL\'s (Universal Resource Links) like www.belkin.com to IP address.";
wd_8 = "More Info";
wd_9 = "Clear Changes";
wd_10 = "Apply Changes";
wd_11 = "Invalid IP address, either the IP address is greater than 224.0.0.0 or the last number of IP address is 0 or 255";

// -------------- WAN Connection PPPoE ----------------
wcp_1 = "PPPoE / PPPoA";
wcp_2 = "PPPoE";
wcp_3 = "PPPoA";
wcp_4 = "To enter your PPPoA settings, type in your information below and click \"Apply changes\".";
wcp_5 = "To enter your PPPoE settings, type in your information below and click \"Apply changes\".";
wcp_6 = "Username";
wcp_7 = "Password";
wcp_8 = "Re-type Password";
wcp_9 = "Service Name";
wcp_10 = "VPI / VCI";
wcp_11 = "Encapsulation";
wcp_12 = "LLC";
wcp_13 = "VC/MUX";
wcp_14 = "MTU";
wcp_15 = "Do not make changes to the MTU setting unless your ISP specifically requires a different setting than 1432.";
wcp_16 = "Disconnect after";
wcp_17 = "minutes of no activity.";
wcp_18 = "Use Static IP Address";
wcp_19 = "Please enter your user name.";
wcp_20 = "Please enter your password.";
wcp_21 = "The password you entered do not match. Please enter your password and re-type the same password.";

// -------------- WAN Connection Dynamic/Fixed IP  ----------------
wcd_1 = "Dynamic/Fixed IP (1483 Bridge)";
wcd_2 = "WAN IP Address is invalid IP address.";
wcd_3 = "WAN subnet mask is invalid IP address.";
wcd_4 = "Default Route is invalid IP address.";
wcd_5 = "Click here to enter your DNS Settings";
wcd_6 = "Use static Default Gateway:";
wcd_7 = "To enter your Dynamic IP settings, type in your information below and click \"Apply changes\".";
wcd_8 = "IP assigned by ISP";
wcd_9 = "Yes";
wcd_10 = "No";

// -------------- WAN Connection Static IP  ----------------
wcs_1 = "Static IP (IPoA)";
wcs_2 = "There is no selection for default gateway";
wcs_3 = "Please enter/validate your DNS address settings on the following screen";
wcs_4 = "To enter your Static IP settings, type in your information below and click \"Apply changes\".";
wcs_5 = "Gateway IP Address";
wcs_6 = "Use WAN Interface:";
wcs_7 = "WAN IP Address";

// -------------- WAN Connection Modem  ----------------
wcm_1 = "Modem Only (Disable Internet Sharing)";
wcm_2 = "To enter your Modem settings, type in your information below and click \"Apply changes\".";
wcm_3 = "Enable Bridge Service";

// -------------- Wireless Main  ----------------
wlm_1 = "Wireless";
wlm_2 = "In this tab you can adjust settings to the Wireless section of the Router.";
wlm_3 = "Channel and SSID";
wlm_4 = "Make adjustments to the wireless channel and SSID(wireless network name).";
wlm_5 = "Security";
wlm_6 = "Change the wireless security settings such as WPA settings or WEP settings.";
wlm_7 = "Use as Access Point";
wlm_8 = "Set the operating mode of the Router to AP mode.";
wlm_9 = "MAC Address Control";
wlm_10 = "Set up a list of clients that you want to allow or deny access to the wireless network.";
wlm_11 = "Easily setup and connect to a WPA-enabled 802.11 network with WPS-certified devices using either Personal Information Number(PIN) method or Push Button Configuration(PBC) method.";
wlm_12 = "Set up a list of MAC addresses that enable the interconnection of access points wirelessly.";

// -------------- Wireless Channel and SSID  ----------------
wlcs_1 = "Current Channel";
wlcs_2 = "SSID should not be empty.";
wlcs_3 = "To make changes to the wireless settings of the router, make the changes here.Click \"Apply Changes\" to save the settings.";
wlcs_4 = "Wireless Channel";
wlcs_5 = "SSID";
wlcs_6 = "Wireless Mode";
wlcs_7 = "802.11n only";
wlcs_8 = "802.11g only";
wlcs_9 = "802.11b only";
wlcs_10 = "Off";
wlcs_11 = "Bandwidth";
wlcs_12 = "Broadcast SSID";
wlcs_13 = "Protected Mode";
wlcs_14 = "Auto";
wlcs_15 = "WMM";
wlcs_16 = "Disable Afterburner(wireless_wifi) for selection";
wlcs_17 = "WMM No Acknowledgement";

// -------------- Wireless Security None  ----------------
wlsn_1 = "Security Mode";
wlsn_2 = "WPA-PSK(no server)";
wlsn_3 = "128bit WEP";
wlsn_4 = "64bit WEP";
wlsn_5 = "WPA(with Radius Server)";
wlsn_6 = "You can configure wireless security/encryption settings here. Security should be enabled to assure maximum wireless security. WPA (Wireless Protected Access) provides dynamic key changes and constitutes the best security solution. In wireless environments, where not all devices support WPA, WEP (Wired Equivalent Privacy) should be used.";

// -------------- Wireless Security WEP 64  ----------------
wlsw64_1 = "Either you have not entered all of the hex digits or some of the hex digits you entered are invalid. A hex digit can be a number from 0-9 or a letter from A-F.";
wlsw64_2 = "It is not a valid passphase";
wlsw64_3 = "Key 1";
wlsw64_4 = "Key 2";
wlsw64_5 = "Key 3";
wlsw64_6 = "Key 4";
wlsw64_7 = "Cannot apply the change since wireless is currently disabled.";
wlsw64_8 = "Note: To automatically generate hex pairs using a PassPhrase, check the box on the left and input the passphrase here";
wlsw64_9 = "Passphrase";
wlsw64_10 = "Generate";

// -------------- Wireless Security WEP 128  ----------------
wlsw128_1 = "(13 hex digit pairs)";

// -------------- Wireless Security WPA PSK  ----------------
wlswp_1 = "WPA Pre-Shared Key should be between 8 and 63 ASCII characters or 64 hexadecimal digits.";
wlswp_2 = "TKIP";
wlswp_3 = "AES";
wlswp_4 = "Authentication";
wlswp_5 = "WPA-PSK";
wlswp_6 = "WPA2-PSK";
wlswp_7 = "Encryption Technique";
wlswp_8 = "Pre-Shared Key (PSK)";
wlswp_9 = "WPA-PSK(no server)";
wlswp_10 = "Wireless Protected Access with a Pre-Shared Key: The key is a password, in the form of a word, phrase or series of letters and numbers. The key must be between 8 and 63 characters long and can include spaces and symbols, or 64 Hex(0-F) only. Each client that connects to the network must use the same key (Pre-Shared Key).";
wlswp_11 = "Obscure PSK";
wlswp_12 = "WPA-PSK + WPA2-PSK";

// -------------- Wireless Security WPA Radius  ----------------
wlsr_1 = "Please input RADIUS key.";
wlsr_2 = "WPA/WPA2-Enterprise(RADIUS)";
wlsr_3 = "Advanced Setting - Wireless Protected Access using a server to distribute keys to the clients: This option requires that a Radius server is running on the network.";
wlsr_4 = "WPA-RADIUS";
wlsr_5 = "WPA2-RADIUS";
wlsr_6 = "Radius Server";
wlsr_7 = "Radius Port";
wlsr_8 = "Radius Key";
wlsr_9 = "Re-Key Interval";
wlsr_10 = "(seconds)";

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
wlap_1 = "Please change the Address entry box in the status bar of your browser manually to the lan address.";
wlap_2 = "Use as Access Point";
wlap_3 = "Enable";
wlap_4 = "Disable";
wlap_5 = "The IP address you choose should be a non-routable IP. Examples of a non routable IP are 192.168.x.x (where x is anything between 0 and 255.), 172.y.x.x (where y is anything from 16 to 31, and x is anything between 0 and 255), 10.x.x.x (where x is anything between 0 and 255.)";
wlap_6 = "Specify IP Address";

// -------------- Wireless MAC filter  ----------------
wlmac_1 = "MAC address control";
wlmac_2 = "MAC Address";
wlmac_3 = "ADD";

// -------------- Firewall Main  ----------------
fwm_1 = "Firewall";
fwm_2 = "Your Router is equipped with a firewall that will protect your network from a wide array of common hacker attacks including Ping of Death (POD) and Denial of Service (DoS) attacks. You can turn the firewall function off if needed. Turning off the firewallprotection will not leave your network completely vulnerable to hacker attacks, but it is recommended that you turn the firewall on whenever possible.";

// -------------- Firewall Virtual Sever  ----------------
fwvs_1 = "Virtual Servers";
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
fwvs_23 = "Close Combat for Windows";
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
fwvs_38 = "DirectX 7 Games";
fwvs_39 = "DirectX 8 Games";
fwvs_40 = "Domain Name Server (DNS)";
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
fwvs_54 = "FTP Server";
fwvs_55 = "GNUtella";
fwvs_56 = "Golf 2001 Edition";
fwvs_57 = "Go2Call";
fwvs_58 = "Half Life";
fwvs_59 = "Half Life Server";
fwvs_60 = "Heretic II Server";
fwvs_61 = "I76";
fwvs_62 = "ICUII Client";
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
fwvs_76 = "Media Player 7";
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
fwvs_90 = "Network Time Protocol (NTP)";
fwvs_91 = "News Server (NNTP)";
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
fwvs_102 = "Quake II (Client and Server)";
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
fwvs_114 = "SNMP Trap";
fwvs_115 = "Speak Freely";
fwvs_116 = "StarCraft";
fwvs_117 = "Starfleet Command";
fwvs_118 = "StarLancer";
fwvs_119 = "SWAT3";
fwvs_120 = "Telnet Server";
fwvs_121 = "TFTP";
fwvs_122 = "The 4th Coming";
fwvs_123 = "Tiberian Sun: C&C III";
fwvs_124 = "Total Annihilation";
fwvs_125 = "Ultima";
fwvs_126 = "Unreal Tournament";
fwvs_127 = "Urban Assault";
fwvs_128 = "VoxPhone 3.0";
fwvs_129 = "Warbirds 2";
fwvs_130 = "Web Server (HTTP)";
fwvs_131 = "WebPhone 3.0";
fwvs_132 = "Westwood Online";
fwvs_133 = "Windows 2000 Terminal Server";
fwvs_134 = "X Windows";
fwvs_135 = "Yahoo Pager";
fwvs_136 = "Yahoo Messenger Chat";
fwvs_137 = "All entries are full.\nPlease remove some entries then try again.";
fwvs_138 = "This function will allow you to route external (Internet) calls for	services such as a web server (port 80), FTP server (port 21), or other applications through your Router to your internal network";
fwvs_139 = "Select One";
fwvs_140 = "Clear";
fwvs_151 = "Type";
fwvs_152 = "Do you want clear all entries?";
fwvs_153 = "Do you want to clear entry";

// -------------- Firewall Client IP filter  ----------------
fwcf_1 = "Client IP Filters";
fwcf_2 = "SUN";
fwcf_3 = "MON";
fwcf_4 = "TUE";
fwcf_5 = "WED";
fwcf_6 = "THU";
fwcf_7 = "FRI";
fwcf_8 = "SAT";
fwcf_9 = "Source address is invalid IP address.";
fwcf_10 = "Destination port is invalid port number or port range.";
fwcf_11 = "The Router can be configured to restrict access to the Internet, e-mail or other network services at specific days and times.";
fwcf_12 = "BOTH";
fwcf_13 = "Block Time";
fwcf_14 = "Always";
fwcf_15 = "Block";
fwcf_16 = "Day";
fwcf_17 = "Time";
fwcf_18 = "Port";

// -------------- Firewall DMZ  ----------------
fwdmz_1 = "DMZ";
fwdmz_2 = "The DMZ feature allows you to specify one computer on your network to be placed outside of the NAT firewall. This may be necessary if the NAT feature is causing problems with an application such as a game or video conferencing application. Use this feature on a temporary basis. The computer in the DMZ is not protected from hacker attacks. To put a computer in the DMZ, enter the last digits of its IP address in the field below and select \"Enable\". Click \"Apply Changes\" for the change to take effect.";
fwdmz_3 = "IP Address of Virtual DMZ Host";
fwdmz_4 = "Static IP";
fwdmz_5 = "Private IP";

// -------------- Firewall DDNS  ----------------
fwddns_1 = "Empty Hostname.";
fwddns_2 = "Empty Domain name.";
fwddns_3 = "Empty username.";
fwddns_4 = "Invalid Email address.";
fwddns_5 = "Empty password.";
fwddns_6 = "Invalid key.";
fwddns_7 = "DDNS";
fwddns_8 = "DDNS (Dynamic DNS) services allow you to use a Domain name even though your Internet IP address is dynamic. You must Register for DDNS service at one of the listed DDNS Services.";
fwddns_9 = "DDNS Service";
fwddns_10 = "Disabled DDNS";
fwddns_11 = "DDNS Status";
fwddns_12 = "Disconnected";
fwddns_13 = "Connected";
fwddns_14 = "Username";
fwddns_15 = "Password";
fwddns_16 = "Domain Name";
fwddns_17 = "Email";
fwddns_18 = "Key";
fwddns_19 = "Update Dynamic DNS";

// -------------- Firewall Wan Ping Blocking  ----------------
fwwpb_1 = "WAN Ping Blocking";
fwwpb_2 = "ADVANCED FEATURE! You can configure the Router not to respond to an ICMP Ping (ping to the WAN port). This offers a heightened level of security.";
fwwpb_3 = "Block ICMP Ping";

// -------------- Firewall Security Log  ----------------
fwsl_1 = "Security Log";
fwsl_2 = "The router keeps a log of all activity within the router such as computers logging in and out and any attempts from the Internet to access the router. The log is viewable below.";
fwsl_3 = "Log File";
fwsl_4 = "Save";
fwsl_5 = "Clear";

// -------------- Utility Main  ----------------
utm_1 = "Utilities";
utm_2 = "This screen lets you manage different parameters of the Router and perform certain administrative functions.";
utm_3 = "Reset Router";
utm_4 = "Sometimes it may be necessary to Reset or Reboot the Router if it begins working improperly. Resetting or Rebooting the Router will not delete any of your configuration settings.";
utm_5 = "Restore Factory Default";
utm_6 = "Using this option will restore all of the settings in the Router to the factory (default) settings. It is recommended that you backup your settings before you restore all of the defaults.";
utm_7 = "Save/Backup Settings";
utm_8 = "You can save your current configuration by using this feature. Saving your configuration will allow you to restore it later if your settings are lost or changed.It is recommended that you backup your current configuration before performing a firmware update.";
utm_9 = "Firmware Update";
utm_10 = "From time to time, Belkin may release new versions of the Router's firmware. Firmware updates contain feature improvements and fixes to problems that may have existed.";
utm_11 = "System Settings";
utm_12 = "The System Settings page is where you can enter a new administrator password, set the time zone, enable remote management function of the Router.";
utm_13 = "Restore Previous Configuration";
utm_14 = "This option will allow you to restore a previously saved configuration.";

// -------------- Utility Reset  ----------------
utrst_1 = "Are you sure you want to restart the Router ?Restarting the Router will not affect your configuration.";
utrst_2 = "Allow up to 60 seconds for the Router to restart. Do not power down the Router before reset completes.";
utrst_3 = "Restart Router";
utrst_4 = "Sometimes it may be necessary to Reset or Reboot the Router if it begins working improperly. Restarting or Rebooting the Router will not delete any of your configuration settings. Click the Restart Router button below to Restart the Router.";

// -------------- Utility Factory Default  ----------------
utfd_1 = "Restore factory defaults";
utfd_2 = "WARNING: All your settings will be lost! Are you sure you want to do this?";
utfd_3 = "Restoring the default settings will take up to 60 seconds. Do not turn off power to the Router during this process.";
utfd_4 = "Will not restore Factory Defaults. No Settings will be Lost!";
utfd_5 = "Using this option will restore all of the settings in the Router to the factory (default) settings. It is recommended that you backup your settings before you restore all of the defaults. To restore the factory default settings, click the \"Restore Defaults\" button below.";
utfd_6 = "Restore Defaults";

// -------------- Utility Save/Backup settings  ----------------
utss_1 = "Save/Backup Current Settings";
utss_2 = "You can save your current configuration by using this feature. Saving your configuration will allow you to restore it later if your settings are lost or changed. It is recommended that you backup your current configuration before performing a firmware update.";
utss_3 = "Save";

// -------------- Utility Previous Settings  ----------------
utps_1 = "Restore previous saved settings";
utps_2 = "Updating settings is in progress and the router will reboot. Please wait for a minute.";
utps_3 = "Do you want to continue and restore settings?";
utps_4 = "After settings are restored, the Router may not respond\nto commands for as long as one minute.\n\nThis is normal. Do not power down the Router during this time.";
utps_5 = "This option will allow you to restore a previously saved configuration.";
utps_6 = "Restore";

// -------------- Utility Firmware Update  ----------------
utfu_1 = "Firmware Update";
utfu_2 = "Check for new firmware version";
utfu_3 = "Check Firmware";
utfu_4 = "Upload software is in progress. Please wait for a minute.";
utfu_5 = "Please specify the upgrade file's location. Either type the file's path and file name or click \"Browse\" to browse to the file's location.";
utfu_6 = "Are you sure you want to continue with upgrading?";
utfu_7 = "At the end of the upgrade, the Router may not respond to commands for as long as one minute. This is normal. Do not turn off or reboot the Router during this time.";
utfu_8 = "From time to time, Belkin may release new versions of the Router's firmware. Firmware updates contain improvements and fixes to problems that may have existed. Click the link below to see if there is a new firmware update available for this Router.";
utfu_9 = "NOTE: Please backup your current settings before updating to a new version of firmware. <b><a  style=\"FONT-SIZE: 11px; color:#0066FF\" href=\"util_save.html\">Click Here</a></b> to go to the Save/Backup current settings page.";
utfu_10 = "Firmware Version";
utfu_11 = "Update Firmware";
utfu_12 = "Update";
utfu_13 = "Firmware update in progress.";
utfu_14 = "DO NOT INTERRUPT OR UNPLUG THE ROUTER, doing so could render the Router inoperable";

// -------------- Utility System Settings  ----------------
utsys_1 = "System Settings";
utsys_2 = "Sunday";
utsys_3 = "Monday";
utsys_4 = "Tuesday";
utsys_5 = "Wednesday";
utsys_6 = "Thursday";
utsys_7 = "Friday";
utsys_8 = "Saturday";
utsys_9 = "January";
utsys_10 = "February";
utsys_11 = "March";
utsys_12 = "Apil";
utsys_13 = "May";
utsys_14 = "June";
utsys_15 = "July";
utsys_16 = "August";
utsys_17 = "September";
utsys_18 = "October";
utsys_19 = "November";
utsys_20 = "December";
utsys_21 = "132.163.4.102-North America";
utsys_22 = "192.5.41.41-North America";
utsys_23 = "192.5.41.209-North America";
utsys_24 = "207.200.81.113-North America";
utsys_25 = "208.184.49.9-North America";
utsys_26 = "129.132.2.21-Europe";
utsys_27 = "130.149.17.8-Europe";
utsys_28 = "128.250.36.3-Australia";
utsys_29 = "137.189.8.174-Asia Pacific";
utsys_30 = "International Date Line West";
utsys_31 = "Midway Island, Samoa";
utsys_32 = "Hawaii";
utsys_33 = "Alaska";
utsys_34 = "Pacific Time, Tijuana";
utsys_35 = "Arizona, Mazatlan";
utsys_36 = "Chihuahua, La Paz";
utsys_37 = "Mountain Time";
utsys_38 = "Central America";
utsys_39 = "Central Time";
utsys_40 = "Guadalajara, Mexico City, Monterrey";
utsys_41 = "Saskatchewan";
utsys_42 = "Bogota, Lima, Quito";
utsys_43 = "Eastern Time";
utsys_44 = "Indiana";
utsys_45 = "Atlantic Time";
utsys_46 = "Caracas, La Paz";
utsys_47 = "Santiago";
utsys_48 = "Newfoundland";
utsys_49 = "Brasilia";
utsys_50 = "Buenos Aires, Georgetown";
utsys_51 = "Greenland";
utsys_52 = "Mid-Atlantic";
utsys_53 = "Azores";
utsys_54 = "Cape Verde Is";
utsys_55 = "Casablanca, Monrovia";
utsys_56 = "Greenwich Mean Time: Dublin, Edinburgh, Lisbon, London";
utsys_57 = "Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna";
utsys_58 = "Belgrade, Bratislava, Budapest, Ljubljana, Prague";
utsys_59 = "Brussels, Copenhagen, Madrid, Paris";
utsys_60 = "Sarajevo, Skopje, Warsaw, Zagreb";
utsys_61 = "West Central Africa";
utsys_62 = "Athens, Istanbul, Minsk";
utsys_63 = "Bucharest";
utsys_64 = "Cairo";
utsys_65 = "Harare, Pretoria";
utsys_66 = "Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius";
utsys_67 = "Jerusalem";
utsys_68 = "Baghdad";
utsys_69 = "Kuwait, Riyadh";
utsys_70 = "Moscow, St. Petersburg, Volgograd";
utsys_71 = "Nairobi";
utsys_72 = "Tehran";
utsys_73 = "Abu Dhabi, Muscat";
utsys_74 = "Baku, Tbilisi, Yerevan";
utsys_75 = "Kabul";
utsys_76 = "Ekaterinburg";
utsys_77 = "Islamabad, Karachi, Tashkent";
utsys_78 = "Chennai, Kolkata, Mumbai, New Delhi";
utsys_79 = "Kathmandu";
utsys_80 = "Almaty, Novosibirsk";
utsys_81 = "Astana, Dhaka";
utsys_82 = "Sri Jayawardenepura";
utsys_83 = "Rangoon";
utsys_84 = "Bangkok, Hanoi, Jakarta";
utsys_85 = "Krasnoyarsk";
utsys_86 = "Beijing, Chongqing, Hong Kong, Urumqi";
utsys_87 = "Irkutsk, Ulaan Bataar";
utsys_88 = "Kuala Lumpur, Singapore";
utsys_89 = "Perth";
utsys_90 = "Taipei";
utsys_91 = "Osaka, Sapporo, Tokyo";
utsys_92 = "Seoul";
utsys_93 = "Yakutsk";
utsys_94 = "Adelaide";
utsys_95 = "Darwin";
utsys_96 = "Brisbane";
utsys_97 = "Canberra, Melbourne, Sydney";
utsys_98 = "Guam, Port Moresby";
utsys_99 = "Hobart";
utsys_100 = "Vladivostok";
utsys_101 = "Magadan";
utsys_102 = "Solomon Is., New Caledonia";
utsys_103 = "Auckland, Wellington";
utsys_104 = "Fiji, Kamchatka, Marshall Is.";
utsys_105 = "Other";
utsys_106 = "None";
utsys_107 = "It is strongly recommended that you set your Administrator password.";
utsys_108 = "Please choose the following remote management type :\n1.Any IP address can remotely manage the router\n2.Only this IP address can remotely manage the router ";
utsys_109 = "Invalid number!Must between 1..65535";
utsys_110 = "First time server is other, but Other field is blank";
utsys_111 = "NTP IP Address is invalid IP address.";
utsys_112 = "Second time server is other, but Other field is blank";
utsys_113 = "Old admin password is wrong.";
utsys_114 = "Password should not be less than 3 characters or lognger than 12 characters.";
utsys_115 = "The passwords do not match.";
utsys_116 = "Login Timeout should be between 1 and 99.";
utsys_117 = "Administrator Password";
utsys_118 = "The Router ships with NO password entered. If you wish to add a password for more security, you can set a password here.";
utsys_119 = "Type in current Password";
utsys_120 = "Type in new Password";
utsys_121 = "Confirm new Password";
utsys_122 = "Login Timeout";
utsys_123 = "1-99minutes";
utsys_124 = "Time and Time Zone";
utsys_125 = "Please set your time Zone. If you are in an area that observes daylight saving check this box.";
utsys_126 = "Time Zone";
utsys_127 = "Daylight Savings";
utsys_128 = "Automatically Adjust Daylight Saving";
utsys_129 = "First NTP time server";
utsys_130 = "Second NTP time server";
utsys_131 = "Remote Management";
utsys_132 = "ADVANCED FEATURE! Remote management allows you to make changes to your Router's settings anywhere on the Internet. Before you enable this function, MAKE SURE YOU HAVE SET THE ADMINISTRATOR PASSWORD.";
utsys_133 = "Enable Remotely Management";
utsys_134 = "Any IP address can remotely manage the router";
utsys_135 = "Only this IP address can remotely manage the Router";
utsys_136 = "Remote Access Port";
utsys_137 = "NAT Enabling";
utsys_138 = "ADVANCED FEATURE ! Allows you to turn the Network Address Translation feature off. In almost every case you would NOT want to turn this feature off.";
utsys_139 = "NAT Enable / Disable";
utsys_140 = "UPnP";
utsys_141 = "ADVANCED FEATURE! Allows you to turn UPnP on or off.";
utsys_142 = "Enable UPnP";
utsys_143 = "Auto Update Firmware Enabling";
utsys_144 = "ADVANCED FEATURE ! Allows you to automatically check the availability of firmware updates for your router.";
utsys_145 = "Auto Update Firmware Enable / Disable";

// -------------- Check New Firmware  ----------------
cnf_1 = "Check Firmware";
cnf_2 = "Cannot connect to the firmware information server, please double check the wan connection.";
cnf_3 = "There is no new firmware update available for this Router!";

// -------------- Help  ----------------
hlp_1 = "Help";
hlp_2 = "HELP OF TERMS";
hlp_3 = "top";
hlp_4 = "Administrator";
hlp_5 = "An administrator performs the service of maintaining a network. In the case of this Router, the person who sets up the Router and makes changes to the settings.";
hlp_6 = "Client";
hlp_7 = "A computer on the network that uses the services of the Router, such as the automatic DHCP server and Firewall.";
hlp_8 = "DHCP";
hlp_9 = "The DHCP server function makes setting up a network very easy by assigning IP addresses to each computer on the network. The DHCP Server can be turned off if necessary. Turning off the DHCP server will require you to manually set a Static IP address in each computer on your network. The IP pool is the range of IP addresses set aside for dynamic assignment to the computers on your network. The default is 2-100 (99 computers) if you want to change this number, you can by entering a new starting and ending IP address and clicking on \"Apply Changes\".";
hlp_10 = "Local Domain Name";
hlp_11 = "You can set a local domain name (network name) for your network. There is no need to change this setting unless you have a specific advanced need to do so. You can name the network anything you want such as \"MY_NETWORK\".";
hlp_12 = "Dial-Up";
hlp_13 = "A connection which uses the public telephone network.";
hlp_14 = "DNS";
hlp_15 = "DNS is an acronym for Domain Name Server. A Domain Name Server is a server located on the Internet that translates URL's (Universal Resource Links) like www.belkin.com to IP addresses. Many ISP's do not require you to enter this information into the Router. If you are using a Static IP connection type, then you may need to enter a specific DNS address and secondary DNS address for your connection to work properly. If your connection type is Dynamic or PPPoE, it is likely that you do not have to enter a DNS address.";
hlp_16 = "DSL Modem";
hlp_17 = "DSL stands for Digital Subscriber Line. A DSL modem uses your existing phone lines to transmit data at high speeds. ";
hlp_18 = "Dynamic IP";
hlp_19 = "An IP address that is automatically obtained from a DHCP server.";
hlp_20 = "Ethernet";
hlp_21 = "A standard for computer networks. Ethernet networks are connected by special cables and hubs, and move data around at up to 10 million bits per second (Mbps).";
hlp_22 = "Firewall";
hlp_23 = "An electronic boundary that prevents unauthorized users from accessing certain files or computers on a network.";
hlp_24 = "Firmware";
hlp_25 = "Software stored in memory. Essential programs that remain even when the system is turned off. Firmware is easier to change than hardware but more permanent than software stored on a disk.";
hlp_26 = "IP Address";
hlp_27 = "The \"IP address\" is the Internal IP address of the Router. To access the advanced setup interface, type this IP address into the address bar of your browser. This address can be changed if needed. To Change the IP address, type in the new IP address and click \"Apply Changes\". The IP address you choose should be a non-routable IP. Examples of a non routable IP are: 192.168.x.x (where x is anything between 0 and 255.) 172.y.x.x (where y is anything from 16 to 31, and x is anything between 0 and 255) 10.x.x.x (where x is anything between 0 and 255.)";
hlp_28 = "ISDN";
hlp_29 = "Integrated Services Digital Network. Digital telecommunications lines that can transmit both voice and digital network services up to 128K, and are much faster and more reliable than high-speed analog modems. ISDN lines are offered by many telephone companies.";
hlp_30 = "ISP";
hlp_31 = "Internet Service Provider. An ISP is a business that provides connectivity to the Internet for individuals and other businesses or organizations.";
hlp_32 = "ISP Gateway Address (see ISP for definition)";
hlp_33 = "The ISP Gateway Address is an IP address for the Internet router located at the ISP's office. This address is required only when using a cable or DSL modem. ";
hlp_34 = "LAN";
hlp_35 = "Local Area Network. A LAN is a group of computers and devices connected together in a relatively small area (such as a house or an office). Your home network is considered a LAN.";
hlp_36 = "MAC Address";
hlp_37 = "MAC stands for Media Access Control. A MAC address is the hardware address of a device connected to a network.";
hlp_38 = "MTU";
hlp_39 = "Maximum Transmission Unit. The largest unit of data that can be transmitted on any particular physical medium.";
hlp_40 = "NAT";
hlp_41 = "Network Address Translation. This process allows all of the computers on your home network to use one IP address. Using the NAT capability of the Belkin Router home network gateway, you can access the Internet from any computer on your home network without having to purchase more IP addresses from your ISP.";
hlp_42 = "Port";
hlp_43 = "A logical channel that is identified by its unique port number. Applications listen on specific ports for information that may be related to it.";
hlp_44 = "Static IP Connection";
hlp_45 = "A Static IP address connection type is less common than other connection types. If your ISP uses static IP addressing, you will need your IP address, Subnet Mask, and ISP gateway address. This information is available from your ISP or on the paperwork that your ISP left with you.";
hlp_46 = "PPPoE (Routing Mode, for multiple PCs)";
hlp_47 = "Most DSL providers use PPPoE as the connection type. If you use a DSL modem to connect to the Internet, your ISP may use PPPoE to log you into the service. If you have an Internet connection in your home or small office that doesn't require a modem, you may also use PPPoE. Your connection type is PPPoE if: 1) Your ISP gave you a user name and password which is required to connect to the Internet. 2) Your ISP gave you software such as WinPOET, Enternet300 that you use to connect to the Internet.  3) You have to double-click on a desktop Icon other than your browser to get on the Internet. To set the Router to use PPPoE, type in your User Name and Password in the spaces provided. If you do not have a Service Name or do not know it, leave the Service Name field blank. For more details on configuring your Router to use PPPoE, see the user manual.";
hlp_48 = "PPPoA";
hlp_49 = "Point-to-Point Protocol Over ATM. Using the PPP dial-up protocol with ATM as the transport. Used by some DSL providers, IP packets travel from the PC over Ethernet to the DSL modem. The DSL modem adds the PPP protocol to the IP packets and transports them to the carrier's DSLAM via ATM.";
hlp_50 = "Idle Time";
hlp_51 = "The Disconnect feature is used to automatically disconnect the router from your ISP when there is no activity for a specified period of time. For instance, placing a checkmark next to this option and entering 5 into the minute field will cause the router to disconnect from the Internet after 5 minutes of no Internet activity. This option should be used if you pay for your Internet service by the minute.";
hlp_52 = "PPPoA (Routing Mode, for multiple PCs)";
hlp_53 = "Disable Internet Sharing(Bridge Mode, for single PC)";
hlp_54 = "Multiple protocol over ATM(Routing Mode, for multiple PCs)";
hlp_55 = "PPTP";
hlp_56 = "Point-to-Point Tunneling Protocol. A version of PPP (Point-to-Point Protocol) that has the ability to encapsulate packets of data formatted for one network protocol in packets used by another protocol. This tunneling technique allows TCP/IP data to be transmitted over a non-TCP/IP network. PPTP can be used to join different physical networks using the Internet as an intermediary.";
hlp_57 = "SNTP";
hlp_58 = "Simple Network Time Protocol. A communication standard that allows for the transmission of real time information over a network or the Internet.";
hlp_59 = "SPI";
hlp_60 = "Stateful Packet Inspection. SPI is the type of corporate-grade Internet security provided by your Belkin Router home network gateway. Using SPI, the gateway acts as a \"firewall,\" protecting";
hlp_61 = "Static IP";
hlp_62 = "An IP address that is manually configured and never changes.";
hlp_63 = "Subnet Mask";
hlp_64 = "ADVANCED FEATURE! There is no need to change the subnet mask. It is possible to change the subnet mask if necessary. Only make changes to the Subnet Mask if you specifically have a reason to do so.";
hlp_65 = "TCP";
hlp_66 = "Transmission Control Protocol. The most common Internet transport layer protocol. TCP is connection-oriented and stream-oriented, and provides for reliable communication over packet-switched networks.";
hlp_67 = "TCP/IP";
hlp_68 = "Transmission Control Protocol over Internet Protocol. This is the standard protocol for data transmission over the Internet.";
hlp_69 = "UDP";
hlp_70 = "User Datagram Protocol. Communications protocol for the Internet network layer, transport layer, and session layer, which makes it possible to send a datagram message from one computer to an application running in another computer. Unlike TCP, UDP is connectionless and does not guarantee reliable communication; the application itself must process any errors and check for reliable delivery.";
hlp_71 = "WAN";
hlp_72 = "Wide Area Network. A network that connects computers located in geographically separate areas, (i.e., different buildings, cities, countries). The Internet is a wide area network.";
hlp_73 = "WAN IP Address";
hlp_74 = "The IP address assigned to the router by the ISP.";
hlp_75 = "Channel and SSID";
hlp_76 = "To change the channel of operation of the Router, select the desired channel from the drop-down menu and select your channel. Click \"Apply Changes\" to save the setting. You can also change the SSID. The SSID is the equivalent to the wireless network's name. You can make the SSID anything you want to. If there are other wireless networks in your area, you should give your wireless network a unique name. Click inside of the SSID box and type in a new name. Click \"Apply Changes\" to make the change.";
hlp_77 = "Using the Wireless Mode Switch";
hlp_78 = "1) 802.11g &amp; 802.11b : Setting the Router to this mode will let 802.11g-, and 802.11b-compliant devices to join the network. 2) Off : This mode will turn OFF the Router's access point, so no wireless devices can join the network. Turning off the wireless function of your Router is a great way to secure your network when you are away from home for a long period of time, or don't want to use the wireless feature of the Router at a certain time.";
hlp_79 = "Broadcast SSID";
hlp_80 = "A feature of wireless networking is the ability for a wireless network adapter in a computer to look for an existing wireless network automatically. This is done by setting the card's SSID setting to &quot;ANY&quot;. Your Router is capable of blocking this &quot;random&quot; searching for a network. If you disable the \"ESSID Broadcast\" feature, the only way a computer can join the network is by setting the computer's SSID to the specific name of the network (like WLAN).Be sure that you know your SSID (network name) before enabling this feature. It is possible to make your wireless network nearly invisible. By turning off the broadcast of the SSID, your network will not appear in a site survey. Site Survey is a feature of many wireless network adapters on the market today. It will scan the \"air\" for any available network and allow the computer to select the network from the site survey. Turning off the broadcast of the SSID will help increase security";
hlp_81 = "USE as Access Point";
hlp_82 = "When using the Router as an Access Point, you must specify an IP address for the Access Point. This IP address must fall into the same range as the network that you will be connecting it to. To access the advanced setup interface of the Router again, type in the IP address in the web browser and login.";
hlp_83 = "Wireless MAC Address Control";
hlp_84 = "The MAC address filter is a powerful security feature that allows you to specify which computers are allowed on the wireless network. Note: This list applies only to wireless computers. This list can be configured so any computer attempting to access the wireless network that is not specified in the filter list will be denied access. When you enable this feature, you must enter the MAC address of each client (computer) to which you want to allow network access. The \"Block\" feature lets you turn on and off access to the network easily for any computer without having to add and remove the computer's MAC address from the list. Setting up an Allow Access List : 1. Select the \"Allow\" radio button to begin setting up a list of computers allowed to connect to the wireless network. 2. Next, in the \"MAC Address\" field that is blank, type in the MAC address of the wireless computer you want to be able to access the wireless network, then click \"Add\". 3. Continue to do this until all of the computers you want to add have been entered. 4. Click \"Apply Changes\" to finish. Setting up a Deny Access List : The \"Deny Access\" list lets you specify computers that you DO NOT want to access the network. Any computer in the list will not be allowed access to the wireless network. All others will. 1. Select the \"Deny\" radio button to begin setting up a list of computers to be denied access to the wireless network. 2. Next, in the \"MAC Address\" field that is blank, type in the MAC address of the wireless computer you want to deny access to the wireless network, then click \"Add\". 3. Continue to do this until all of the computers you want to deny access to have 4. Click \"Apply Changes\"to finish.";
hlp_85 = "ACK Mode";
hlp_86 = "There are two acknowledgement (ACK) modes that can be employed to get the best multimedia performance on your network: Burst ACK and Immediate ACK. Immediate ACK is the default (factory) setting and is recommended for normal network operation. Changing the ACK mode from Immediate ACK to Burst ACK may affect long-range throughput. Use Immediate ACK when long-range performance of your network is most important to you. Burst ACK mode will lower overhead by not acknowledging every packet sent over the network. When there is a very good link between the Router and the client, Burst ACK can provide a throughput boost. If an application, such as streaming multiple high-data video streams, requires maximum bandwidth, use Burst ACK mode. Keep in mind that long-range performance may be affected when using Burst ACK mode.";
hlp_87 = "QoS (Quality of Service) Configuration";
hlp_88 = "QoS prioritizes important data on your network such as multimedia content and voice-over-IP (VoIP) so it will not be interfered with by other data being sent over the network. Based on 802.11e, this feature can be turned on or off and you can choose the acknowledgement mode you want to use. If you plan to stream multimedia content or use VoIP on your network, the QoS feature should be enabled.";
hlp_89 = "Encryption";
hlp_90 = "Using Encryption can help secure your wireless network. Only one type of security may be selected at a time. Therefore the customer must select a mode that is supported on all network devices on the wireless network. This Belkin product has 5 possible Security settings: 1) Disabled. No encryption is enabled in this mode. Open networks where all users are welcome sometimes prefer to not enable encryption. 2) WPA PSK - Home (no server). WPA (Wireless protected Access) PSK is a recent standards-based security technique where each packet of information is encrypted with a different code, or key. Since the key is constantly changing, WPA is very secure. There are two types of WPA, WPA-PSK (Pre-Shared Key), and WPA-Radius Server. Obviously the difference being that one requires a server and one does not. WPA-PSK is for home and small business users who do not have a server. The PSK encryption key is generated automatically from a string of characters or Pass Phrase. Obviously the biggest security risk in WPA PSK is if someone finds out your Pass Phrase. a. TKIP verses AES. WPA setup requires the user to select whether to encrypt using TKIP or AES. The WPA standard specifies TKIP, so that is the default. Additionally TKIP should provide better compatibility between wireless products from different vendors since many wireless products will never be upgraded to AES. AES is a new encryption technique based on the un-ratified 802.11i standard. New WPA standards are being considered using AES. Although AES is not as popular, some users may prefer to use this technique. Either way, all networks devices must use the same technique. b. Pre-Shared Key. Enter any word or phrase up to 40 characters. The same PSK must also be used for every other wireless network device on the network. Watch out for upper and lower case differences (\"n\" is different than \"N\".) Remember, the easiest way to break your security is for someone to guess your PSK. 3) 128-bit WEP. Until recently, 128-bit WEP (Wired Equivalent Privacy) was the standard for wireless encryption. If not all of your wireless devices support WPA, 128bit WEP still offers very good security option. It will require you to enter hex numbers, or you can generate them automatically. 4) 64-bit WEP. Belkin only recommends 64-bit mode on networks where some devices do not support either WPA or 128bit WEP. 5) WPA - Radius Server. (This mode is accessed from the Advanced Button). WPA server is only for networks using a Radius Server. All parameter for this mode should be obtained from the administrator of your Radius Server. Unlike WPA PSK, WPA server passes the key from the server to the clients instead of generating it automatically.";
hlp_91 = "Virtual Servers";
hlp_92 = "This function will allow you to route external (Internet) calls for services such as a web server (port 80), FTP server (Port 21), or other applications through your Router to your internal network. Since your internal computers are protected by a firewall, machines from the Internet cannot get to them because they cannot be 'seen'. If you need to configure the Virtual Server function for a specific application, you will need to contact the application vendor to find out which port settings you need. To manually enter settings, enter the IP address in the space provided for the internal machine, the port type (TCP or UDP) select the LAN & Public port(s) required topass, select Enable and click \"Apply Changes\". You can only pass one port per internal IP address. Opening ports in your firewall can pose a security risk. You can enable and disable settings very quickly. It is recommended that you disable the settings when you are not using a specific application.";
hlp_93 = "Using Dynamic DNS";
hlp_94 = "The Dynamic DNS service allows you to alias a dynamic IP address to a static host name in any of the many domains DynDNS.org offers, allowing your network computers to be more easily accessed from various locations on the Internet. DynDNS.org provides this service, for up to five host names, free to the Internet community.The Dynamic DNSSM service is ideal for a home website, file server, or to make it easy to access your home PC and stored files while you're at work. Using the service can ensure that your host name always points to your IP address, no matter how often your ISP changes it. When your IP address changes, your friends and associates can always locate you by visiting yourname.dyndns.org instead! To register free for your Dynamic DNS host name, please visit http://www.dyndns.org. Setting up the Router's Dynamic DNS Update Client. To register free for your Dynamic DNS host name, please visit http://www.dyndns.org. Setting up the Router's Dynamic DNS Update Client You must register with DynDNS.org's free update service before using this feature. Once you have your registration, follow the directions below. 1.Enter your DynDNS.org user name in the \"User Name\" field (1). 2.Enter your DynDNS.org password in the \"Password\" field (2). 3.Enter the DynDNS.org domain name you set up with DynDNS.org in the \"Domain Name\" field (3). 4.Click \"Update Dynamic DNS\" to update your IP address. Whenever your IP address assigned by your ISP changes, the Router will automatically update DynDNS.org's servers with your new IP address. You can also do this manually by clicking the \"Update Dynamic DNS\" button (4).";
hlp_95 = "Client IP filters";
hlp_96 = " The Router can be configured to restrict access to the Internet, e-mail or other network services at specific days and times. Restriction can be set for a single computer, a range of computers, or multiple computers. To restrict Internet access to a single computer for example, enter the IP address of the computer you wish to restrict access to in the IP fields. Next enter 80 and 80 in the Port fields. Select TCP. Select Block. You can also select Always to block access all of the time. Select the day to start on top, the time to start on top, the day to end on the bottom and the time to stop on the bottom. Click \"Apply Changes\". The computer at the IP address you specified will now be blocked from Internet access at the times you specified. Note: be sure you have selected the correct time zone under Utilities> System Settings> Time Zone.";
hlp_97 = "MAC Address Filtering";
hlp_98 = "The MAC Address Filter is a powerful security feature that allows you to specify which computers are allowed on the network. Any computer attempting to access the network that is not specified in the filter list will be denied access. When you enable this feature, you must enter the MAC address of each client on your network to allow network access to each or copy the MAC address by selecting the name of the computer from the \"DHCP Client List\". To enable this feature, select \"Enable\". Next, click \"Apply Changes\" to save the settings.";
hlp_99 = "DMZ";
hlp_100 = "If you have a client PC that cannot run an Internet application properly from behind the firewall, you can open the client up to unrestricted two-way Internet access. This may be necessary if the NAT feature is causing problems with an application such as a game or video conferencing application. Use this feature on a temporary basis. The computer in the DMZ is not protected from hacker attacks. To put a computer in the DMZ, enter the last digits of its LAN IP address in the Static IP field and click \"Apply Changes\" for the change to take effect.";
hlp_101 = "Administrator Password";
hlp_102 = "The Router ships with NO password entered. If you wish to add a password for more security, you can set a password here. Keep your password in a safe place as you will need this password if you need to log into the router in the future. It is also recommended that you set a password if you plan to use the Remote management feature of this Router. The login timeout option allows you to set the period of time that you can be logged into the Router's advanced setup interface. The timer starts when there has been no activity. For example, you  have made some changes in the advanced setup interface, then left your computer alone without clicking \"Logout\". Assuming the timeout is set to 10 minutes, then 10 minutes after you leave, the login session will expire. You will have to login to the router again to make any more changes. The login timeout option is for security purposes and the default is set to 10 minutes. As a note, only one computer can be logged into the Router's advanced setup interface at one time";
hlp_103 = "NAT Enabling";
hlp_104 = "Before you enable this function, MAKE SURE YOU HAVE SET THE ADMINISTRATOR PASSWORD. Network Address Translation (NAT) is the method by which the router shares the single IP address assigned by your ISP with the computers on your network. Advanced users should only use this function. This function should only be used if your ISP assigns you multiple IP addresses or you need NAT disabled for an advanced system configuration. If you have a single IP address and you turn NAT off, the computers on your network will not be able to access the Internet. Other problems may also occur. Turning off NAT will disable your firewall functions.";
hlp_105 = "UPnP";
hlp_106 = "UPnP (Universal Plug-and-Play) is a technology that offer seamless operation of voice messaging, video messaging, games, and other applications that are UPnP compliant. Some applications require the Router's firewall to be configured in a specific way to operate properly. This usually requires opening TCP and UDP ports and in some instances setting trigger ports. An application that is UPnP compliant has the ability to communicate with the Router, basically \"telling\" the Router which way it needs the firewall configured. The Router ships with the UPnP feature disabled. If you are using any applications that are UPnP compliant, and wish to take advantage of the UPnP features, you can enable the UPnP feature. Simply select \"Enable\" in the \"UPnP Enabling\" section of the Utilities page. Click \"Apply Changes\" to save the change.";
hlp_107 = "Automatic Firmware Update Notification";
hlp_108 = "The Router has the capability built-in to automatically check for a new version of firmware and alert you that the new firmware is available. When you log into the Router advanced interface, the router will perform a check to see if new firmware is available. If new firmware is available, you will be notified. You can choose to download the new version or ignore it. The router ships with this feature disabled. If you want to enable it, select \"Enable\" and click \"Apply Changes\".";
hlp_109 = "Remote Management";
hlp_110 = "Remote management allows you to make changes to your Router's settings from anywhere on the Internet. There are two methods of remotely managing the Router. The first is to allow access to the Router from anywhere on the Internet by selecting \"Any IP address can remotely manage the Router\". By typing in your WAN IP address from any computer on the Internet, you will be presented with a login screen where you need to type in the password of your Router. The second method is to allow a specific IP address only to remotely manage the Router. This is more secure, but less convenient. To use this method, enter the IP address you know you will be accessing the Router from in the space provided and select \"Only this IP address can remotely manage the Router\". Before you enable this function, it is STRONGLY RECOMMENDED that you set your administrator password. Leaving the password empty will potentially open your Router to intrusion.";
hlp_111 = "WLAN";
hlp_112 = "Wireless Local Area Network. A local area network that connects computers close together via radio (such as 802.11b).";
hlp_113 = "BLOCK ICMP PING";
hlp_114 = "Computer hackers use what is known as &quot;Pinging&quot; to find potential victims on the Internet. By pinging a specific IP address and receiving a response from the IP address, a hacker can determine that something of interest might be there. The Router can be set up so it will not respond to an ICMP Ping from the outside. This heightens the level of security of your Router. To turn off the ping response , select \"Block ICMP Ping\" and click \"Apply Changes\". The Router will not respond to an ICMP ping.";
hlp_115 = "Protected Mode";
hlp_116 = "NOTE: In most situations, best performance(throughput) is achieved with Protected Mode OFF. If you are operating in an environment with HEAVY 802.11b traffic or interference, best performance may be achieved with Protected Mode ON.";
hlp_117 = "Time and Time Zone";
hlp_118 = "The Router keeps time by connecting to a Simple Network Time Protocol (SNTP) server. This allows the Router to synchronize the system clock to the global Internet. The synchronized clock in the Router is used to record the security log and control client filtering. Select the time zone that you reside in. The system clock may not update immediately. Allow at least 15 minutes for the to contact the time servers on the Internet and get a response. You cannot set the clock yourself.";
hlp_119 = "Wi-Fi Multimedia (WMM)";
hlp_120 = "This feature enables the Quality of Service (QoS) function that is used for multimedia applications, such as Voice-over-IP (VoIP) and video. This allows the network packets of the multimedia application to have priority over regular data network packets, allowing multimedia applications to run smoother and with fewer errors.";
hlp_121 = "WMM No-Acknowledgement";
hlp_122 = "No-Acknowledgement refers to the acknowledge policy used at the MAC level. Enabling no-acknowledgement can result in more efficient throughput but higher error rates in a noisy Radio Frequency (RF) environment.";

// -- Restore factory defaults Successfully  --
utfrds_1 = "Restore factory defaults Successfully";
utfrds_2 = "The restore is complete when the router icon stops blinking.";


// -- Reset Successfully --
utrs_1 ="Reset Successfully";
utrs_2 ="The reset is complete when the power light stops blinking.";
utrs_3 ="Router is rebooting";
utrs_4 ="seconds remaining.";

// -- Restored Settings Successfully --
utrss_1 ="Restored Settings Successfully";
utrss_2 ="The restored settings is complete when the power light stops blinking.";

// -- Apply ?-
apply_1 = "Apply Changes";
apply_2 = "Applying changes. Please wait ......";

}
