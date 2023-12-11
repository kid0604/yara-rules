import "pe"

rule PKLITEv120
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITE v1.20 executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 06 [2] 72 ?? B4 09 BA [2] CD 21 B4 4C CD 21 }

	condition:
		$a0 at pe.entry_point
}
