rule Windows_Generic_Threat_8b790aba
{
	meta:
		author = "Elastic Security"
		id = "8b790aba-02b4-4c71-a51e-3a56ea5728ec"
		fingerprint = "8581397f15b9985bafa5248f0e7f044bf80c82e441d2216dc0976c806f658d2e"
		creation_date = "2024-01-09"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "ec98bfff01d384bdff6bbbc5e17620b31fa57c662516157fd476ef587b8d239e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 7A 66 62 50 4A 64 73 72 78 77 7B 7B 79 55 36 46 42 50 4A 3F 20 2E 6E 3E 36 65 73 7A }
		$a2 = { 50 36 7B 77 64 71 79 64 46 4A 73 64 79 62 45 7A 77 63 62 64 }

	condition:
		all of them
}
