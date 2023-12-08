import "pe"

rule PEnguinCryptv10
{
	meta:
		author = "malware-lu"
		description = "Detects PEnguinCryptv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 93 [2] 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }

	condition:
		$a0 at pe.entry_point
}
