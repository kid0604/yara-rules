rule APT_MAL_CN_Unit78020_Sep15
{
	meta:
		description = "Detects malware used by Unit78020"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://threatconnect.com/camerashy/?utm_campaign=CameraShy"
		date = "2015-09-24"
		modified = "2023-01-31"
		score = 80
		old_rule_name = "Unit78020_Malware_Gen1"
		hash1 = "2b15e614fb54bca7031f64ab6caa1f77b4c07dac186826a6cd2e254090675d72"
		hash2 = "76c586e89c30a97e583c40ebe3f4ba75d5e02e52959184c4ce0a46b3aac54edd"
		hash3 = "7b73bf2d80a03eb477242967628da79924fbe06cc67c4dcdd2bdefccd6e0e1af"
		hash4 = "2625a0d91d3cdbbc7c4a450c91e028e3609ff96c4f2a5a310ae20f73e1bc32ac"
		hash5 = "5c62b1d16e6180f22a0cb59c99a7743f44cb4a41e4e090b9733d1fb687c8efa2"
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
		$sa1 = "dMozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.0; .NET CLR 1.1.4322)" wide fullword
		$sa2 = "x-www-form-urlencoded/r/n" wide fullword
		$sa3 = "/%d%s%d" ascii fullword
		$sa4 = "dMozilla" wide fullword
		$sa5 = "Accept-Language:En-us" wide fullword
		$sb1 = "%USERPROFILE%\\Application Data\\Mozilla\\Firefox\\Profiles" wide fullword
		$sb2 = "\\Office Start.lnk" wide fullword
		$sb3 = "%02d-%02d-%02d %02d:%02d" wide fullword
		$sc1 = "\\MSN Talk Start.lnk" wide fullword
		$sc2 = "-GetModuleFileNameExW" ascii fullword
		$sc3 = "dwError1 = %d" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or all of ($sa*) or all of ($sb*) or all of ($sc*))
}
