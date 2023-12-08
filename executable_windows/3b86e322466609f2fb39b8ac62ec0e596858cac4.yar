rule PoisonIvy_Sample_APT_2
{
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "333f956bf3d5fc9b32183e8939d135bc0fcc5770"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "pidll.dll" fullword ascii
		$s1 = "sens32.dll" fullword wide
		$s2 = "9.0.1.56" fullword wide
		$s3 = "FileDescription" fullword wide
		$s4 = "OriginalFilename" fullword wide
		$s5 = "ZwSetInformationProcess" fullword ascii
		$s6 = "\"%=%14=" fullword ascii
		$s7 = "091A1G1R1_1g1u1z1" fullword ascii
		$s8 = "gHsMZz" fullword ascii
		$s9 = "Microsoft Media Device Service Provider" fullword wide
		$s10 = "Copyright (C) Microsoft Corp." fullword wide
		$s11 = "MFC42.DLL" fullword ascii
		$s12 = "MSVCRT.dll" fullword ascii
		$s13 = "SpecialBuild" fullword wide
		$s14 = "PrivateBuild" fullword wide
		$s15 = "Comments" fullword wide
		$s16 = "040904b0" fullword wide
		$s17 = "LegalTrademarks" fullword wide
		$s18 = "CreateThread" fullword ascii
		$s19 = "ntdll.dll" fullword ascii
		$s20 = "_adjust_fdiv" ascii

	condition:
		uint16(0)==0x5a4d and filesize <47KB and all of them
}
