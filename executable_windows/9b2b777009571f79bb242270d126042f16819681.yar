import "pe"

rule WWPACKv303
{
	meta:
		author = "malware-lu"
		description = "Detects WWPACKv303 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 BB [2] 53 }

	condition:
		$a0 at pe.entry_point
}
