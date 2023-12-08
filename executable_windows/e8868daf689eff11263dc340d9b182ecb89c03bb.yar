rule Susp_Indicators_EXE
{
	meta:
		description = "Detects packed NullSoft Inst EXE with characteristics of NetWire RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://pastebin.com/8qaiyPxs"
		date = "2018-01-05"
		score = 60
		hash1 = "6de7f0276afa633044c375c5c630740af51e29b6a6f17a64fbdd227c641727a4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion"
		$s2 = "Error! Bad token or internal error" fullword ascii
		$s3 = "CRYPTBASE" fullword ascii
		$s4 = "UXTHEME" fullword ascii
		$s5 = "PROPSYS" fullword ascii
		$s6 = "APPHELP" fullword ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x4550 and filesize <700KB and all of them
}
