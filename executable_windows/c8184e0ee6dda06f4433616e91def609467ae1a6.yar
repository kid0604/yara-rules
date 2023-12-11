import "pe"

rule PKLITE3211
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PKLITE3211 in the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }

	condition:
		$a0 at pe.entry_point
}
