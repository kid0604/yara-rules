import "pe"

rule Kryptonv02
{
	meta:
		author = "malware-lu"
		description = "Detects Kryptonv02 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }

	condition:
		$a0 at pe.entry_point
}
