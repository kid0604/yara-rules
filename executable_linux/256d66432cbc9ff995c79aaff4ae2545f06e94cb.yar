rule Linux_Generic_Threat_11041685
{
	meta:
		author = "Elastic Security"
		id = "11041685-8c0d-4de0-ba43-b8f676882857"
		fingerprint = "d446fd63eb9a036a722d76183866114ab0c11c245d1f47f8949b0241d5a79e40"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "296440107afb1c8c03e5efaf862f2e8cc6b5d2cf979f2c73ccac859d4b78865a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 72 65 73 6F 6C 76 65 64 20 73 79 6D 62 6F 6C 20 25 73 20 74 6F 20 25 70 }
		$a2 = { 73 79 6D 62 6F 6C 20 74 61 62 6C 65 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65 2C 20 61 62 6F 72 74 69 6E 67 21 }

	condition:
		all of them
}
