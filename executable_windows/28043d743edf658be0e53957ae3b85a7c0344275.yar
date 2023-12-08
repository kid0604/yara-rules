rule Unit78020_Malware_Gen1
{
	meta:
		description = "Detects malware by Chinese APT PLA Unit 78020 - Generic Rule"
		author = "Florian Roth"
		reference = "http://threatconnect.com/camerashy/?utm_campaign=CameraShy"
		date = "2015-09-24"
		hash1 = "2b15e614fb54bca7031f64ab6caa1f77b4c07dac186826a6cd2e254090675d72"
		hash2 = "76c586e89c30a97e583c40ebe3f4ba75d5e02e52959184c4ce0a46b3aac54edd"
		hash3 = "2625a0d91d3cdbbc7c4a450c91e028e3609ff96c4f2a5a310ae20f73e1bc32ac"
		hash4 = "5c62b1d16e6180f22a0cb59c99a7743f44cb4a41e4e090b9733d1fb687c8efa2"
		hash5 = "7b73bf2d80a03eb477242967628da79924fbe06cc67c4dcdd2bdefccd6e0e1af"
		hash6 = "88c5be84afe20c91e4024160303bafb044f98aa5fbf8c9f9997758a014238790"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "greensky27.vicp.net" fullword wide
		$x2 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
		$x3 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
		$x4 = "serch.vicp.net" fullword wide
		$x5 = "greensky27.vicp.net" fullword wide
		$x6 = "greensky27.vicp.net.as" fullword wide
		$x7 = "greensky27.vcip.net" fullword wide
		$x8 = "pnoc-ec.vicp.net" fullword wide
		$x9 = "aseanph.vicp.net" fullword wide
		$x10 = "pnoc.vicp.net" fullword wide
		$a1 = "dMozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$a2 = "User-Agent: Netscape" fullword ascii
		$a3 = "Accept-Language:En-us/r/n" fullword wide
		$a4 = "\\Office Start.lnk" fullword wide
		$a5 = "\\MSN Talk Start.lnk" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7" fullword ascii
		$s3 = "%USERPROFILE%\\Application Data\\Mozilla\\Firefox\\Profiles" fullword wide
		$s4 = "Content-Type:application/x-www-form-urlencoded/r/n" fullword wide
		$s5 = "Hello World!" fullword wide
		$s6 = "Accept-Encoding:gzip,deflate/r/n" fullword wide
		$s7 = "/%d%s%d" fullword ascii
		$s8 = "%02d-%02d-%02d %02d:%02d" fullword wide
		$s9 = "WininetMM Version 1.0" fullword wide
		$s10 = "WININETMM" fullword wide
		$s11 = "GET %dHTTP/1.1" fullword ascii
		$s12 = "POST http://%ws:%d/%d%s%dHTTP/1.1" fullword ascii
		$s13 = "PeekNamePipe" fullword ascii
		$s14 = "Normal.dot" fullword ascii
		$s15 = "R_eOR_eOR_eO)CiOS_eO" fullword ascii
		$s16 = "DRIVE_RAMDISK" fullword wide
		$s17 = "%s %s %s %s %d %d %d %d " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <250KB and 1 of ($x*)) or 2 of ($a*) or 6 of ($s*)
}
