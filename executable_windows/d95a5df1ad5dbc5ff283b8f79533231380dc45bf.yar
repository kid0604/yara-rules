import "pe"

rule APT17_Unsigned_Symantec_Binary_EFA
{
	meta:
		description = "Detects APT17 malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/puVc9q"
		date = "2017-10-03"
		hash1 = "128aca58be325174f0220bd7ca6030e4e206b4378796e82da460055733bb6f4f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Copyright (c) 2007 - 2011 Symantec Corporation" fullword wide
		$s2 = "\\\\.\\SYMEFA" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them and pe.number_of_signatures==0)
}
