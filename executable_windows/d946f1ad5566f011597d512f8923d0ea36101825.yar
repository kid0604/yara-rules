import "pe"

rule VxTravJack883
{
	meta:
		author = "malware-lu"
		description = "Detects VxTravJack883 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB ?? 9C 9E 26 [2] 51 04 ?? 7D ?? 00 ?? 2E [4] 8C C8 8E C0 8E D8 80 [4] 74 ?? 8A [3] BB [2] 8A ?? 32 C2 88 ?? FE C2 43 81 }

	condition:
		$a0 at pe.entry_point
}
