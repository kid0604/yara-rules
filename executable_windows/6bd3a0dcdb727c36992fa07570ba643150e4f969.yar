rule PROMETHIUM_NEODYMIUM_Malware_5
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "a8b7e3edaa18c6127e98741503c3a2a66b7720d2abd967c94b8a5f2e99575ac5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Winxsys.exe" fullword wide
		$s2 = "%s\\ssleay32.dll" fullword wide
		$s3 = "%s\\libeay32.dll" fullword wide
		$s4 = "Windows Index Services" fullword wide
		$s5 = "<F RAT" fullword ascii
		$s6 = "WININDX-088FA840-B10D-11D3-BC36-006067709674" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB and 3 of them )
}
