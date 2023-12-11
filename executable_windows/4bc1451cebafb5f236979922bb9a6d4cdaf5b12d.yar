import "pe"

rule DIETv100d
{
	meta:
		author = "malware-lu"
		description = "Detects DIET malware version 1.0.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC 06 1E 0E 8C C8 01 [3] BA [2] 03 [14] 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
