import "pe"

rule DIETv144v145f
{
	meta:
		author = "malware-lu"
		description = "Detects DIET version 1.44 and 1.45"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA [2] 03 D0 52 }

	condition:
		$a0 at pe.entry_point
}
