import "pe"

rule PIRITv15
{
	meta:
		author = "malware-lu"
		description = "Detects PIRITv15 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 4D CD 21 E8 [2] FD E8 [2] B4 51 CD 21 }

	condition:
		$a0 at pe.entry_point
}
