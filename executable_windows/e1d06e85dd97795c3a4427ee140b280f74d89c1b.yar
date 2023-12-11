import "pe"

rule PKLITEv150Devicedrivercompression
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITE v1.50 device driver compression"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }

	condition:
		$a0 at pe.entry_point
}
