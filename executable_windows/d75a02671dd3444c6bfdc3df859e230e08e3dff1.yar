rule FourElementSword_ElevateDLL_alt_1
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Elevate.dll" fullword wide
		$x2 = "ResN32.dll" fullword wide
		$s1 = "Kingsoft\\Antivirus" fullword wide
		$s2 = "KasperskyLab\\protected" fullword wide
		$s3 = "Sophos" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 1 of ($x*) and all of ($s*)) or ( all of them )
}
