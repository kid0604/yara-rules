import "pe"

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCASM
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point in Borland Delphi or Microsoft Visual C++ ASM files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 [2] 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

	condition:
		$a0 at pe.entry_point
}
