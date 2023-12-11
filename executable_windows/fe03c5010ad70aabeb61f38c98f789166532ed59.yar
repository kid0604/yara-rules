import "pe"

rule Shrinkv20
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Shrinkv20 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [2] 50 9C FC BE [2] 8B FE 8C C8 05 [2] 8E C0 06 57 B9 }

	condition:
		$a0 at pe.entry_point
}
