import "pe"

rule PKLITEv1501
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITE v1.50.1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 B8 [2] BA [2] 05 [2] 3B 06 [2] 72 ?? B4 ?? BA [2] CD 21 B8 [2] CD 21 }

	condition:
		$a0 at pe.entry_point
}
