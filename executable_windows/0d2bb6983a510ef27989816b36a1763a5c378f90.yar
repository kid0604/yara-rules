import "pe"

rule LameCryptLaZaRus
{
	meta:
		author = "malware-lu"
		description = "Detects the LameCryptLaZaRus malware based on specific byte sequence at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 66 9C BB 00 [2] 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 [2] 40 00 FF E0 }

	condition:
		$a0 at pe.entry_point
}
