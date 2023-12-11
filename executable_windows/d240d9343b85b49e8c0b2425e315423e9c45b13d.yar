import "pe"

rule PKLITEv200b_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITEv200b_alt_1 malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 B8 [2] BA [2] 05 [2] 3B 06 02 00 72 ?? B4 09 BA [2] CD 21 B8 01 4C CD 21 [30] 59 2D [2] 8E D0 51 2D [2] 8E C0 50 B9 }

	condition:
		$a0 at pe.entry_point
}
