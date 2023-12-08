import "pe"

rule PKLITEv200bextra
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITE v2.00b extra"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 B8 [2] BA [2] 05 [2] 3B 06 02 00 72 ?? B4 09 BA [2] CD 21 B8 01 4C CD 21 [30] EA [4] F3 A5 C3 59 2D [2] 8E D0 51 2D [2] 50 80 }

	condition:
		$a0 at pe.entry_point
}
