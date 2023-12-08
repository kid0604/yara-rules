import "pe"

rule PMODEWv112116121133DOSextender
{
	meta:
		author = "malware-lu"
		description = "Detects PMODE/W DOS extender"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC 16 07 BF [2] 8B F7 57 B9 [2] F3 A5 06 1E 07 1F 5F BE [2] 06 0E A4 }

	condition:
		$a0 at pe.entry_point
}
