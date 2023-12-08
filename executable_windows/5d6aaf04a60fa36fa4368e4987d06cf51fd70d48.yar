rule PROMETHIUM_NEODYMIUM_Malware_4
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "15ededb19ec5ab6f03db1106d2ccdeeacacdb8cd708518d065cacb1b0d7e955d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\windows\\temp\\winrar.exe" fullword wide
		$s2 = "info@aadobetech.com" fullword ascii
		$s3 = "%s\\ssleay32.dll" fullword wide
		$s4 = "%s\\libeay32.dll" fullword wide
		$s5 = "%s\\fprot32.exe" fullword wide
		$s6 = "ADOBE Corp.1" fullword ascii
		$s7 = "Adobe Flash Player1\"0 " fullword ascii
		$s8 = "Windows Index Services" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 4 of them ) or (6 of them )
}
