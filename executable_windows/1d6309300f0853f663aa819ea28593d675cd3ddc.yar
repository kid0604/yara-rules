import "pe"

rule AVPACKv120
{
	meta:
		author = "malware-lu"
		description = "Detects AVPACKv120 malware based on the entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 [2] FC F3 A5 06 BB [2] 53 CB }

	condition:
		$a0 at pe.entry_point
}
