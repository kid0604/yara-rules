import "pe"

rule TheGuardLibrary
{
	meta:
		author = "malware-lu"
		description = "Detects TheGuardLibrary malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 E8 [4] 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }

	condition:
		$a0 at pe.entry_point
}
