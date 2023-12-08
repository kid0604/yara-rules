rule APT_Kaspersky_Duqu2_SamsungPrint
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "ce39f41eb4506805efca7993d3b0b506ab6776ca"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Installer for printer drivers and applications" fullword wide
		$s1 = "msi4_32.dll" fullword wide
		$s2 = "HASHVAL" fullword wide
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <82KB and all of them
}
