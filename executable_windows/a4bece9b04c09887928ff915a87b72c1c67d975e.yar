import "pe"

rule RAZOR1911encruptor
{
	meta:
		author = "malware-lu"
		description = "Detects the RAZOR1911encruptor malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] BF [2] 3B FC 72 ?? B4 4C CD 21 BE [2] B9 [2] FD F3 A5 FC }

	condition:
		$a0 at pe.entry_point
}
