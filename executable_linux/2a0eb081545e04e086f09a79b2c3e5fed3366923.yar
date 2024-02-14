rule Linux_Generic_Threat_a8faf785
{
	meta:
		author = "Elastic Security"
		id = "a8faf785-997d-4be8-9d10-c6e7050c257b"
		fingerprint = "c393af7d7fb92446019eed23bbf216d941a9598dd52ccb610432985d0da5ce04"
		creation_date = "2024-01-23"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "6028562baf0a7dd27329c8926585007ba3e0648da25088204ebab2ac8f723e70"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 53 57 56 83 E4 F0 83 EC 10 E8 00 00 00 00 5B 81 C3 53 50 00 00 8B 45 0C 8B 4D 10 8B 55 08 65 8B 35 14 00 00 00 89 74 24 08 8D 75 14 89 74 24 04 8B 3A 56 51 50 52 FF 97 CC 01 00 00 83 }

	condition:
		all of them
}
