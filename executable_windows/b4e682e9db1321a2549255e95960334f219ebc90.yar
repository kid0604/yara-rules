import "pe"

rule DBPEv210DingBoy
{
	meta:
		author = "malware-lu"
		description = "Detects DingBoy malware based on its entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 20 [32] 9C 55 57 56 52 51 53 9C E8 [4] 5D 81 ED [4] EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C }

	condition:
		$a0 at pe.entry_point
}
