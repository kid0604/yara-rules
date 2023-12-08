import "pe"

rule ExeShieldv27_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ExeShield v2.7 alternative 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

	condition:
		$a0 at pe.entry_point
}
