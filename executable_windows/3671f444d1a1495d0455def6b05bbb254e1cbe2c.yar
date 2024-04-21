rule case_19438_files_MalFiles_HTCTL32
{
	meta:
		description = "19438 - file HTCTL32.DLL"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ReadSocket - Connection has been closed by peer" fullword ascii
		$s2 = "HTCTL32.dll" fullword ascii
		$s3 = "POST http://%s/fakeurl.htm HTTP/1.1" fullword ascii
		$s4 = "htctl32.dll" fullword wide
		$s5 = "CloseGatewayConnection - shutdown(%u) FAILED (%d)" fullword ascii
		$s6 = "CloseGatewayConnection - closesocket(%u) FAILED (%d)" fullword ascii
		$s7 = "putfile - _read FAILED (error: %d)" fullword ascii
		$s8 = "ReadSocket - Error %d reading response" fullword ascii
		$s9 = "ctl_adddomain - OpenGatewayConnection2 FAILED (%d)" fullword ascii
		$s10 = "NSM247Ctl.dll" fullword ascii
		$s11 = "pcictl_247.dll" fullword ascii
		$s12 = "User-Agent: NetSupport Manager/1.3" fullword ascii
		$s13 = "ReadMessage - missing or invalid content length" fullword ascii
		$s14 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\release\\htctl32.pdb" fullword ascii
		$s15 = "ctl_putfile - _topen FAILED (error: %d)" fullword ascii
		$s16 = "ctl_putfile - _filelength FAILED (error: %d)" fullword ascii
		$s17 = "TraceBuf - WriteFile failed (%d)" fullword ascii
		$s18 = "(Httputil.c) Error %d reading HTTP response header" fullword ascii
		$s19 = "ReadMessage - Unexpected result code in response \"%s\" " fullword ascii
		$s20 = "ctl_removeoperator - INVALID PARAMETER" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 8 of them
}
