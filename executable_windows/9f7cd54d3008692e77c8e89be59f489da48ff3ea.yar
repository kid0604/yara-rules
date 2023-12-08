import "pe"

rule DBPEv233DingBoy
{
	meta:
		author = "malware-lu"
		description = "Detects DingBoy malware by checking for a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 20 [2] 40 [29] 9C 55 57 56 52 51 53 9C E8 [4] 5D 81 ED [4] 9C 6A 10 73 0B EB 02 C1 51 E8 06 [3] C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 }

	condition:
		$a0 at pe.entry_point
}
