import "pe"

rule E2CbyDoP
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [2] BF [2] B9 [2] FC 57 F3 A5 C3 }

	condition:
		$a0 at pe.entry_point
}
