//added by Alex 08/31/2006

function Logout()
{
	var loc = 'Timelogout.cgi?usrUserName=fail';
	window.location.href = loc;
}
function Login()
{
  window.location.href = "login.html"; 
}

function showHead(wanStatus,helpItem)
{
	var strHtml;
	
	strHtml = '<table border="0" cellspacing="0" cellpadding="0" align="top" width="100%" height="100%">'+
  				'<tr>'+ 
    				'<td colspan="3" bordercolor="#FFFFFF" height="64">'+ 
      					'<table width="100%" border="0" cellspacing="0" cellpadding="0" bgcolor="#CCCCCC">'+
          					'<tr>'+ 
          						'<td rowspan="3" width="20" valign="bottom">'+
          							'<a href="http://www.belkin.com"><img src="head_logo.gif" border="0" width="140" height="64"></a>'+
          						'</td>'+
          						'<td rowspan="3" width="1" valign="bottom"></td>'+
            					'<td colspan="4" align="right" nowrap>&nbsp;'+ 
            					'</td>'+
          					'</tr>';
    document.write(strHtml); 
    
   

  		strHtml =   		'<tr>'+
          						'<td colspan="4" height="18">'+
          							'<img src="title.gif" height="20" width="265">'+
          						'</td>'+
          					'</tr>';
       document.write(strHtml); 
  
	strHtml =           	'<tr>'+
          						'<td height="23" align="right" nowrap class="top_nav"> '+
            						'<nobr><a href="home.html" class="top_nav">'+menu_1+'</a>'+ 
            						'| <a href="help.html" class="top_nav">'+menu_2+'</script></a>';
    document.write(strHtml);        						 
	
	if(helpItem=='indexa' || helpItem=='Login' )
	{
     	strHtml ='| <a href="JavaScript:Login();" class="top_nav">'+menu_3+'</a> &nbsp; &nbsp;';
     	document.write(strHtml); 
    }
    else
    {
		if (helpItem!='Help' && helpItem!='Parental Control') 
		{
      		strHtml ='| <a href="javascript:Logout();" class="top_nav">'+menu_4+'</a> &nbsp; &nbsp;';
     		document.write(strHtml);
		}
		else 
			document.write('&nbsp; &nbsp;');
    }

    if(wanStatus == 'Up')
    {
     	strHtml =      				'<span class="top_nav">'+menu_5+': <b>'+
            						'<font face="verdana,arial" size="2" color="#0066FF">'+menu_6+'</font></b></span></nobr> ';
        document.write(strHtml);
	} 
	else
	{
		strHtml =      				'<span class="top_nav">'+menu_5+': <b>'+
            						'<font face="verdana,arial" size="2" color="#FF0000">'+menu_7+'</font></b></span></nobr> ';
        document.write(strHtml);
	}
	
        strHtml =  				'</td>'+
          					'</tr>'+
      					'</table>'+
    				'</td>'+
  				'</tr>';
  	document.write(strHtml);
}


function showMenu(menuSection,menuItem,isAPmode)
{
	var yellow   ='#FFFFFF';
	var white    ='#FFFFFF';
	var red    	 ='#6699FF';
	var blue   	 ='#666666';
	var darkBlue ='#666666';
	var black    ='#CCCCCC';
	var bssid = '00:11:50:20:3B:B1';
	
	var strHtml;
		strHtml='<tr>'+ 
    				'<td valign="top" width="130" bgcolor="#666666" height="100%">'+ 
      				'<table width="140" border="0" cellspacing="0" cellpadding="0" align="left">';
      	document.write(strHtml);
    
    // Router Mode
    if(isAPmode =='1' || isAPmode =='2')
    {
    
		// LAN Section   
   		if(menuSection=='LAN')
   		{
   			printMenuSection('lan_main.html', menu_8, yellow);
   			
   			if(menuItem=='LAN Settings')
   			{
   				printMenuDisabledItem('lan_settings.html', menu_9, red, darkBlue);
        	}
        	else
        	{
        		printMenuItem('lan_settings.html', menu_9, black, blue);
        	}
        	if(menuItem=='DHCP Client List')
       	 	{
       	 		printMenuDisabledItem('lan_dhcp.html', menu_10, red, darkBlue);
       		}
       		else
       		{
       			printMenuItem('lan_dhcp.html', menu_10, black, blue);
       		}
    	}
    	else
    	{ 
    		printMenuSection('lan_main.html', menu_8, white); 
    		
        	printMenuItem('lan_settings.html', menu_9, black, white);
        	printMenuItem('lan_dhcp.html', menu_10, black, white);
		}
		
		// WAN Section   
		if(menuSection=='WAN')
		{
			printMenuSection('wan_main.html', menu_11, yellow);
			
    		if(menuItem=='Connection Type')
    		{
    			printMenuDisabledItem('wan_conn.html', menu_12, red, darkBlue);
    		}
    		else
    		{
    			printMenuItem('wan_conn.html', menu_12, black, blue);
    		}
    		
    		if(menuItem=='DNS')
    		{
    			printMenuDisabledItem('wan_dns.html', menu_13, red, darkBlue);
    		}
    		else
    		{
    			printMenuItem('wan_dns.html', menu_13, black, blue);
    		}
    		
    	}
		else
		{	
			printMenuSection('wan_main.html', menu_11, white);
    		
    		printMenuItem('wan_conn.html', menu_12, black, white);
    		printMenuItem('wan_dns.html', menu_13, black, white);
        }
	}
	
	// router or ap mode
 
      	// WLAN Section   
      	if(bssid != 'WLAN Not Available') {
		if(menuSection=='WLAN')
		{
			printMenuSection('wireless_main.html', menu_14, yellow);
			
        	if(menuItem=='Channel and SSID')
    		{
        		printMenuDisabledItem('wireless_chan.html', menu_15, red, darkBlue);
         	}
         	else
         	{
         		printMenuItem('wireless_chan.html', menu_15, black, blue);
         	}
         	
            if(menuItem=='Security')
    		{
         		printMenuDisabledItem('wireless_encrypt.html', menu_16, red, darkBlue);
         	}
         	else
         	{
         		printMenuItem('wireless_encrypt.html', menu_16, black, blue);
         	}

/*
            if(menuItem=='WPS')
    		{
         		printMenuDisabledItem('wireless_wps.html', menu_33, red, darkBlue);
         	}
         	else
         	{
         		printMenuItem('wireless_wps.html', menu_33, black, blue);
         	}
*/
         	if(menuItem=='Use as Access Point')
    			{
         		printMenuDisabledItem('wireless_apt.html', 'Use as Access Point', red, darkBlue);
         	}
         	else
         	{
         		printMenuItem('wireless_apt.html', 'Use as Access Point', black, blue);
         	}

         	if(menuItem=='MAC Address Control')
    			{
         		printMenuDisabledItem('wireless_mac_ctrl.html', menu_18, red, darkBlue);
         	}
         	else
         	{
         		printMenuItem('wireless_mac_ctrl.html', menu_18, black, blue);
         	}
			
         	if(menuItem=='WDS')
    			{
         		printMenuDisabledItem('wireless_wds.html', 'Wireless Bridge', red, darkBlue);
         	}
         	else
         	{
         		printMenuItem('wireless_wds.html', 'Wireless Bridge', black, blue);
         	}
			
		}
		else
		{
			printMenuSection('wireless_main.html', menu_14, white);
    		
    		printMenuItem('wireless_chan.html', menu_15, black, white);
    		printMenuItem('wireless_encrypt.html', menu_16, black, white); 
			//printMenuItem('wireless_wps.html', menu_33, black, white); 
			printMenuItem('wireless_apt.html', 'Use as Access Point', black, white);
         	printMenuItem('wireless_mac_ctrl.html', menu_18, black, white);            
		 	printMenuItem('wireless_wds.html', 'Wireless Bridge', black, white);
      
      	}
      } 	      	
    //router mode    			
    if(isAPmode =='1' || isAPmode =='2') 
    {   	
       	// Fire Wall Section   
		if(menuSection=='Fire')
		{
			printMenuSection('fw_main.html', menu_19, yellow);
			          	
          	if(menuItem=='Virtual Servers')
    		{
    			printMenuDisabledItem('fw_virt.html', menu_20, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('fw_virt.html', menu_20, black, blue);
          	}
          	
          	if(menuItem=='Client IP Filters')
    		{
    			printMenuDisabledItem('fw_clientip.html', menu_21, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('fw_clientip.html', menu_21, black, blue);
          	}
          	
          	if(menuItem=='DMZ')
    			{
    			printMenuDisabledItem('fw_dmz.html', menu_22, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('fw_dmz.html', menu_22, black, blue);
          	}
          	if(menuItem=='DDNS')
    			{
    			printMenuDisabledItem('fw_ddns.html', menu_23, red, darkBlue);
          	}
			
          	else
          	{
          		printMenuItem('fw_ddns.html', menu_23, black, blue);
          	}
          	if(menuItem=='WAN Ping Blocking')
    		{
    			printMenuDisabledItem('fw_ping.html', menu_24, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('fw_ping.html', menu_24, black, blue);
          	}
          	
          	if(menuItem=='Security Log')
    		{
    			printMenuDisabledItem('fw_security.html', menu_25, red, darkBlue);
        	}
        	else
        	{
        		printMenuItem('fw_security.html', menu_25, black, blue);
        	}
		}
		else
		{
         	printMenuSection('fw_main.html', menu_19, white);
          	printMenuItem('fw_virt.html', menu_20, black, white);
          	printMenuItem('fw_clientip.html', menu_21, black, white);
          	printMenuItem('fw_dmz.html', menu_22, black, white);
          	printMenuItem('fw_ddns.html', menu_23, black, white);
          	printMenuItem('fw_ping.html', menu_24, black, white);
        	printMenuItem('fw_security.html', menu_25, black, white);
        }
	} 
	
        // router or ap mode
      	// Utilities Section  
      	if(menuSection=='Util')
      	{			
      		printMenuSection('util_main.html', menu_26, yellow);
      		
        	if(isAPmode =='1' || isAPmode =='2') // router 
        	{ 
        		if(menuItem=='Parental Control')
    			{	
      				printMenuDisabledItem('util_parentalc.html', 'Parental Control', red, darkBlue);
          		}
        		else
          		{
          			;//printMenuItem('util_parentalc.htm', 'Parental Control', black, blue);
          		}
          	}
        	if(menuItem=='Restart Router')
    		{
    			if('1'=='1' )
    			{	
      				printMenuDisabledItem('util_reset.html', menu_27, red, darkBlue);
          		}
          		else
          		{
          			printMenuDisabledItem('util_reset.html', 'Restart AP', red, darkBlue);
          		}
          	}
          	else
          	{
          		if('1'=='1' )
    			{	
      				printMenuItem('util_reset.html', menu_27, black, blue);
          		}
          		else
          		{
          			printMenuItem('util_reset.html', 'Restart AP', black, blue);
          		}
          	}
          	if(menuItem=='Restore Factory Default')
    		{
    			printMenuDisabledItem('util_factory.html', menu_28, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('util_factory.html', menu_28, black, blue);
          	}			
          	if(menuItem=='Save/Backup Settings')
    		{	
    			printMenuDisabledItem('util_save.html', menu_29, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('util_save.html', menu_29, black, blue);
          	}
          	if(menuItem=='Restore Previous Settings')
    		{
    			printMenuDisabledItem('util_prev.html', menu_30, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('util_prev.html', menu_30, black, blue);
          	}
          	if(menuItem=='Firmware Update')
    		{
    			printMenuDisabledItem('util_firmware.html', menu_31, red, darkBlue);
          	}
          	else
          	{
          		printMenuItem('util_firmware.html', menu_31, black, blue);
          	}
          	if(menuItem=='System Settings')
    		{
    			if(isAPmode =='1' || isAPmode =='2')
    			{
    				printMenuDisabledItem('util_system.html', menu_32, red, darkBlue);
        		}
        		else
        		{
        			printMenuDisabledItem('util_system.html', menu_32, red, darkBlue);
        		}
        	}
        	else
        	{
        		if(isAPmode =='1' || isAPmode =='2')
    			{
    				printMenuItem('util_system.html', menu_32,  black, blue);
    				
        		}
        		else
        		{
        			printMenuItem('util_system.html', menu_32,  black, blue);
        		}
        	}
        	printMenuDisabledItem('', '', black, white); //TJ added temproraly
      	}
      	else
      	{
      		printMenuSection('util_main.html', menu_26, white);
      		
        	if(isAPmode =='1' || isAPmode =='2') // router 
        	{
          		;//printMenuItem('util_parentalc.htm', show31, black, white); TJ temp remove
          	}
          	if('1'=='1' )
    		    {	
      			   printMenuItem('util_reset.html', menu_27, black, white);
          	}
          	else
          	{
          			printMenuItem('util_reset.html', 'Restart AP', black, white);
          	}
          	    printMenuItem('util_factory.html', menu_28, black, white);
          	    printMenuItem('util_save.html', menu_29, black, white);
          	    printMenuItem('util_prev.html', menu_30, black, white);
          	    printMenuItem('util_firmware.html', menu_31, black, white);
        	  if(isAPmode =='1' || isAPmode =='2')
    		    {
    			      printMenuItem('util_system.html', menu_32,  black, white);
        	  }
        	  else
        	  {
        		    printMenuItem('util_system.html', menu_32,  black, white);
        	  }
         		printMenuDisabledItem('', '', black, white); //TJ added temproraly
        }
    
   		strHtml=		'</table>'+
    				'</td>'+
    				'<td valign="top" width="1" height="100%"></td>';
   	document.write(strHtml);
   	
   
}

function showTail()
{
	var strHtml;
	strHtml = '</tr>'+
			'</table>'+
		'</body>'+
	'</html>';
	document.write(strHtml);
}

function printMenuSection(link, content, color)
{
	var strHtml;
	strHtml=		'<tr>'+ 
          				'<td colspan="2" height="20" width="140" bgcolor="#666666">&nbsp;'+          					
          					'<a href="' + link + '" class="section"><font color="' + color + '">'+content+'</font></a>'+
          				'</td>'+
        			'</tr>';
    document.write(strHtml);
}

function printMenuItem(link, content, color, background)
{
	var strHtml;	
    strHtml=		'<tr>'+  
          				'<td width="5" bgcolor="#666666">&nbsp;</td>'+ 
          				'<td class="leftLink" bgcolor="#666666">'+ 
          					'<a href="' + link + '" class="leftLink">' + content + '</a>'+ 
          				'</td>'+ 
         			'</tr>'; 
    document.write(strHtml);
}
function printMenuDisabledItem(link, content, color, background)
{
	var strHtml;	
    strHtml=		'<tr>'+  
          				'<td width="5" bgcolor="#666666">&nbsp;</td>'+ 
          				'<td class="leftLink" bgcolor="#666666">'+ 
          					'<font color="' + color + '">' + content + '</font>'+ 
          				'</td>'+ 
         			'</tr>'; 
    document.write(strHtml);
}
