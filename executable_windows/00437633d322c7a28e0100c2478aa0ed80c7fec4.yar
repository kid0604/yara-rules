rule APT_Malware_PutterPanda_MsUpdater_1
{
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b55072b67543f58c096571c841a560c53d72f01a"
		os = "windows"
		filetype = "executable"

	strings:
		$x0 = "msupdate.exe" fullword wide
		$x1 = "msupdate" fullword wide
		$s1 = "Microsoft Corporation. All rights reserved." fullword wide
		$s2 = "Automatic Updates" fullword wide
		$s3 = "VirtualProtectEx" fullword ascii
		$s4 = "Invalid parameter" fullword ascii
		$s5 = "VirtualAllocEx" fullword ascii
		$s6 = "WriteProcessMemory" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 1 of ($x*) and 4 of ($s*)) or (1 of ($x*) and all of ($s*))
}
