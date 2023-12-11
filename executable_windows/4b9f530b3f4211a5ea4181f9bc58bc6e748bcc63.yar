import "pe"

rule PKLITEv114v120
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITE v1.14 and v1.20"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 06 [2] 72 ?? B4 09 BA [2] CD 21 CD 20 }

	condition:
		$a0 at pe.entry_point
}
