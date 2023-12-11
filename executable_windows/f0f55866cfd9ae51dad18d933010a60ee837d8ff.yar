rule PROMETHIUM_NEODYMIUM_Malware_1
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "e12031da58c0b08e8b610c3786ca2b66fcfea8ddc9ac558d08a29fd27e95a3e7"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\Windows\\system32\\syswindxr32.dll" fullword wide
		$s2 = "c:\\windows\\temp\\TrueCrypt-Setup-7.1a-tamindir.exe" fullword wide
		$s3 = "%s\\ssleay32.dll" fullword wide
		$s4 = "%s\\libeay32.dll" fullword wide
		$s5 = "%s\\fprot32.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <10000KB and 3 of them ) or ( all of them )
}
