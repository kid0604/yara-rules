import "pe"

rule MALWARE_Win_ComeBacker
{
	meta:
		author = "ditekSHen"
		description = "Detects ComeBacker variants. Associated with ZINC / Lazarus"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ENGINE_get_RAND" ascii
		$s2 = "./{IES" fullword ascii
		$s3 = "TODO: <Company name>" fullword wide
		$s4 = "@Microsoft Corperation. All rights reserved." fullword wide
		$s5 = "Microsoft@Windows@Operating System" fullword wide
		$x1 = "C:\\Windows\\System32\\rundll32.exe %s,%s %s %s" fullword ascii wide
		$x2 = "ASN2_TYPE_new" fullword ascii wide
		$x3 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or all of ($x*))
}
