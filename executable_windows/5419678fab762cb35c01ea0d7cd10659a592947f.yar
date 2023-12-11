import "pe"

rule ExeShieldv17
{
	meta:
		author = "malware-lu"
		description = "Detects ExeShield v17 protected executables"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }

	condition:
		$a0 at pe.entry_point
}
