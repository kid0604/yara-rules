rule PROMETHIUM_NEODYMIUM_Malware_6
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "dbd8cbbaf59d19cf7566042945e36409cd090bc711e339d3f2ec652bc26d6a03"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\Windows\\system32\\syswindxr32.dll" fullword wide
		$s2 = "c:\\windows\\temp\\TrueCrypt-7.2.exe" fullword wide
		$s3 = "%s\\ssleay32.dll" fullword wide
		$s4 = "%s\\libeay32.dll" fullword wide
		$s5 = "%s\\fprot32.exe" fullword wide
		$s6 = "Windows Index Services" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <7000KB and 4 of them )
}
