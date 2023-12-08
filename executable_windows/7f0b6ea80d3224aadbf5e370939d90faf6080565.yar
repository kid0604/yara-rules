import "pe"

rule VxPredator2448
{
	meta:
		author = "malware-lu"
		description = "Detects VxPredator2448 malware based on the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0E 1F BF [2] B8 [2] B9 [2] 49 [4] 2A C1 4F 4F [2] F9 CC }

	condition:
		$a0 at pe.entry_point
}
