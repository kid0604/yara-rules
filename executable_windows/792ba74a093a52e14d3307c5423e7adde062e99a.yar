rule Unit78020_Malware_Gen2
{
	meta:
		description = "Detects malware by Chinese APT PLA Unit 78020 - Generic Rule"
		author = "Florian Roth"
		reference = "http://threatconnect.com/camerashy/?utm_campaign=CameraShy"
		date = "2015-09-24"
		super_rule = 1
		hash1 = "76c586e89c30a97e583c40ebe3f4ba75d5e02e52959184c4ce0a46b3aac54edd"
		hash2 = "7b73bf2d80a03eb477242967628da79924fbe06cc67c4dcdd2bdefccd6e0e1af"
		hash3 = "981e2fa1ae4145359036b46e8b53cc5da37dd2311204859761bd91572f025e8a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "-GetModuleFileNameExW" fullword ascii
		$s1 = "\\MSN Talk Start.lnk" fullword wide
		$s2 = ":SeDebugPrivilege" fullword wide
		$s3 = "WinMM Version 1.0" fullword wide
		$s4 = "dwError1 = %d" fullword ascii
		$s5 = "*Can't Get" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
