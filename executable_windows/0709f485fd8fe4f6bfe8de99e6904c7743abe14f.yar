rule case_19438_files_MalFiles_TCCTL32
{
	meta:
		description = "19438 - file TCCTL32.DLL"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Openport - Bind failed, error %d, port %d, socket %d" fullword ascii
		$s2 = "*** %s %s Logic Error from %s (%s). next wanted (%x) already acked" fullword ascii
		$s3 = "UDP Retry Error. session %d inactive. now-recv = %d ms, dwNow - dwFrameTicks = %d ms" fullword ascii
		$s4 = "ctl_close - unclosed sessionz %dz, inuse=%d, skt=%d, flgs=x%x" fullword ascii
		$s5 = "INETMIB1.DLL" fullword ascii
		$s6 = "*** %s %s Logic Error from %s (%s). next wanted must be in nacks" fullword ascii
		$s7 = "TCCTL32.dll" fullword ascii
		$s8 = "tcctl32.dll" fullword wide
		$s9 = "Error: UDP Packet incomplete - %d cf %d" fullword ascii
		$s10 = "*** Error. ctl_read overflow of %d ***" fullword ascii
		$s11 = "GetHostInfo.hThread" fullword ascii
		$s12 = "Error. Terminating GetHostByName thread" fullword ascii
		$s13 = "PCICAPI.DLL" fullword ascii
		$s14 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\release\\tcctl32.pdb" fullword ascii
		$s15 = "*** %s %s Logic Error from %s (%s). Ack %x cannot be next wanted" fullword ascii
		$s16 = "Error: UDP Packet too long - %d cf %d" fullword ascii
		$s17 = "%s %dz inactive. now-recv = %d ms, dwNow - dwFrameTicks = %d ms" fullword ascii
		$s18 = "Error. UDP frame received on unknown input stream, Socket %d, Control %s, Control Port %d" fullword ascii
		$s19 = "*** %s %s End Udp %s, Client receive stats to follow ***" fullword ascii
		$s20 = "*** %s %s Start Udp %s, wireless=%d ***" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 8 of them
}
