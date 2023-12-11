import "pe"

rule WerusCrypter10byKas
{
	meta:
		author = "malware-lu"
		description = "Detects WerusCrypter 1.0 by Kas"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

	condition:
		$a0 at pe.entry_point
}
