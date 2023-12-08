rule APT_Kaspersky_Duqu2_msi3_32
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "ProcessUserAccounts" fullword ascii
		$s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s4 = "msi3_32.dll" fullword wide
		$s5 = "RunDLL" fullword ascii
		$s6 = "MSI Custom Action v3" fullword wide
		$s7 = "msi3_32" fullword wide
		$s8 = "Operating System" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <72KB and all of them
}
