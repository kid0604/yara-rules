rule Windows_Generic_Threat_0ff403df
{
	meta:
		author = "Elastic Security"
		id = "0ff403df-cf94-43f3-b8b0-b94068f333f1"
		fingerprint = "3e16fe70b069579a146682d2bbeeeead63c432166b269a6d3464463ccd2bd2f8"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "b3119dc4cea05bef51d1f373b87d69bcff514f6575d4c92da4b1c557f8d8db8f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 81 EC 00 02 00 00 56 8B F1 57 C6 85 00 FF 63 C7 06 0C 22 41 00 0C 66 69 B6 66 01 7C 06 02 77 03 96 66 69 B6 7B 14 04 F2 05 6B 06 69 96 66 69 6F 07 C5 08 30 66 69 96 66 09 01 0A 67 0B }

	condition:
		all of them
}
