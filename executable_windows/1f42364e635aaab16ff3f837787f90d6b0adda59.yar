import "pe"

rule TMTPascalv040
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of TMTPascalv040 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0E 1F 06 8C 06 [2] 26 A1 [2] A3 [2] 8E C0 66 33 FF 66 33 C9 }

	condition:
		$a0 at pe.entry_point
}
