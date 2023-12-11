import "pe"

rule WWPACKv300v301Extractable
{
	meta:
		author = "malware-lu"
		description = "Detects the WWPACK v3.00 and v3.01 extractable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 6A ?? 06 06 8C D3 83 [2] 53 6A ?? FC }

	condition:
		$a0 at pe.entry_point
}
