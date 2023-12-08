rule PROMETHIUM_NEODYMIUM_Malware_2
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "1aef507c385a234e8b10db12852ad1bd66a04730451547b2dcb26f7fae16e01f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "winasys32.exe" fullword ascii
		$s2 = "alg32.exe" fullword ascii
		$s3 = "wmsrv32.exe" fullword ascii
		$s4 = "vmnat32.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them ) or (3 of them )
}
