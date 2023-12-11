import "pe"

rule PCryptv351
{
	meta:
		author = "malware-lu"
		description = "Detects PCryptv351 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }

	condition:
		$a0 at pe.entry_point
}
