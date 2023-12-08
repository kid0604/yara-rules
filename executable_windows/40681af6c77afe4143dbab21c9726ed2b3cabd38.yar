import "pe"

rule EquationGroup_PortMap_Lp
{
	meta:
		description = "EquationGroup Malware - file PortMap_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Privilege elevation failed" fullword wide
		$s2 = "Portmap ended due to max number of ports" fullword wide
		$s3 = "Invalid parameters received for portmap" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 2 of them )
}
