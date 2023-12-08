rule APT_Kaspersky_Duqu2_procexp
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
		hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
		hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "svcmsi_32.dll" fullword wide
		$x2 = "msi3_32.dll" fullword wide
		$x3 = "msi4_32.dll" fullword wide
		$x4 = "MSI.dll" fullword ascii
		$s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "Sysinternals installer" fullword wide
		$s3 = "Process Explorer" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*)) and ( all of ($s*))
}
