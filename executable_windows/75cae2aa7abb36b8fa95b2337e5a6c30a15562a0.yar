import "pe"

rule XCRv013
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 93 71 08 [8] 8B D8 78 E2 [4] 9C 33 C3 [4] 60 79 CE [4] E8 01 [4] 83 C4 04 E8 AB FF FF FF [4] 2B E8 [4] 03 C5 FF 30 [4] C6 ?? EB }

	condition:
		$a0 at pe.entry_point
}
