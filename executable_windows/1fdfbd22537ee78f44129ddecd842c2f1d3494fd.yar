rule CN_Honker_Injection_transit
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection_transit.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f4fef2e3d310494a3c3962a49c7c5a9ea072b2ea"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "<description>Your app description here</description> " fullword ascii
		$s4 = "Copyright (C) 2003 ZYDSoft Corp." fullword wide
		$s5 = "ScriptnackgBun" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3175KB and all of them
}
