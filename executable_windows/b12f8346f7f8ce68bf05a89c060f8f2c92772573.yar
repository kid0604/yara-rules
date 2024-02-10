rule Windows_Generic_Threat_83c38e63
{
	meta:
		author = "Elastic Security"
		id = "83c38e63-6a18-4def-abf2-35e36210e4cf"
		fingerprint = "9cc8ee8dfa6080a18575a494e0b424154caecedcc8c8fd07dd3c91956c146d1e"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2121a0e5debcfeedf200d7473030062bc9f5fbd5edfdcd464dfedde272ff1ae7"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 32 65 65 64 36 35 36 64 64 35 38 65 39 35 30 35 62 34 33 39 35 34 32 30 31 39 36 66 62 33 35 36 }
		$a2 = { 34 2A 34 4A 34 52 34 60 34 6F 34 7C 34 }

	condition:
		all of them
}
