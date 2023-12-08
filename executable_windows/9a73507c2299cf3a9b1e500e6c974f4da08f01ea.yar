import "pe"

rule PEncryptv10
{
	meta:
		author = "malware-lu"
		description = "Detects PEncryptv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }

	condition:
		$a0 at pe.entry_point
}
