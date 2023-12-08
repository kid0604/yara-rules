import "pe"

rule EXEStealthv11
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of EXEStealthv11 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}
