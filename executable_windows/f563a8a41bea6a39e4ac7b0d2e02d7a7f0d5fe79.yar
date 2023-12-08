import "pe"

rule VxGotcha879
{
	meta:
		author = "malware-lu"
		description = "Detects VxGotcha malware based on specific code pattern at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5B 81 EB [2] 9C FC 2E [7] 8C D8 05 [2] 2E [4] 50 2E [6] 8B C3 05 [2] 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21 }

	condition:
		$a0 at pe.entry_point
}
