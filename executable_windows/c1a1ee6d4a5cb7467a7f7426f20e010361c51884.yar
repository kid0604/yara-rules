import "pe"

rule Inbuildv10hard
{
	meta:
		author = "malware-lu"
		description = "Detects Inbuildv10hard malware by analyzing the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B9 [2] BB [2] 2E [2] 2E [2] 43 E2 }

	condition:
		$a0 at pe.entry_point
}
