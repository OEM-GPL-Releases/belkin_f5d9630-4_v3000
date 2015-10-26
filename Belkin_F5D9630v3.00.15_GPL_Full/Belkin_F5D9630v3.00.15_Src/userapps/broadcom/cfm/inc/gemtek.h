#ifndef __GEMTEK_H__
#define __GEMTEK_H__

#define FOR_BELKIN 1
  
#if FOR_BELKIN
#define FOR_RALINK 1

#define FOR_UK	0
  
  /* Add additional firmware header check */
  #define CHECK_GEMTEK_HEADER 1

  /* Automatically add the administrator's MAC address to the list when apply MAC address filtering */
  #define FIX_BELKIN_MAC_FILTERING 1
  
  /* Use the Belkin style Client IP Filter */
  #define FIX_BELKIN_CLIENT_IP_FILTER 1

  /* Use the Belkin style DDNS */
  #define FIX_BELKIN_DDNS 1

  /* Use wget to retrieve the firmware version information from the belkin web site */
  #define FIX_BELKIN_CHECK_NEW_FIRMWARE 1


  #define ADD_REMOTE_MANAGEMENT_PORT 1

  #define BELKIN_EZI_WIRELESS_11N	0

  #define BELKIN_EZI_WIRELESS_WPS	1

  #define BELKIN_EZI_MULTILANG	1

  
#endif

#define HTTP_USE_LOCATION 1 // do not use 'location.assign', use 'window.location'


#define COUNTRY "UK"
#define FIRMWARE_VERSION "3.00.15" 
#define SUB_FIRMWARE_VERSION "3.00.15" 

#define DEVICE_NAME "F5D9630"


#if CHECK_GEMTEK_HEADER

#define MAGIC "9630"

#define CRC(crc, ch)	 (crc = (crc >> 8) ^ crctab[(crc ^ (ch)) & 0xff])

#define MAGIC_SIZE 16

typedef struct _HEADER_ {
  char magic[MAGIC_SIZE];
  unsigned long crc;	
} Header;

#endif /* CHECK_GEMTEK_HEADER */


#endif //__GEMTEK_H__
