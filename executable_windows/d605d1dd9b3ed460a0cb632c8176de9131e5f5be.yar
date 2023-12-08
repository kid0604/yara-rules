import "pe"

rule iPBProtect013017forgot
{
	meta:
		author = "malware-lu"
		description = "Detects the iPBProtect 013017forgot malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
