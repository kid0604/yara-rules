import "pe"

rule PKLITEv100v103
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITE v1.00 - v1.03 compressed executables"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] BA [2] 8C DB 03 D8 3B }

	condition:
		$a0 at pe.entry_point
}
