import "pe"

rule DIETv100v100d
{
	meta:
		author = "malware-lu"
		description = "Detects DIET malware version 1.0.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF [2] 3B FC 72 ?? B4 4C CD 21 BE [2] B9 [2] FD F3 A5 FC }

	condition:
		$a0 at pe.entry_point
}
