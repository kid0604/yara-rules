import "pe"

rule PEncrypt10JunkCode
{
	meta:
		author = "malware-lu"
		description = "Detects PEncrypt 1.0 Junk Code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 [4] BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 [3] FF }

	condition:
		$a0 at pe.entry_point
}
