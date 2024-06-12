rule Linux_Generic_Threat_d2dca9e7
{
	meta:
		author = "Elastic Security"
		id = "d2dca9e7-6ce6-49b9-92a8-f0149f2deb42"
		fingerprint = "2a1182f380b07d7ad1f46514200e33ea364711073023ad05f4d82b210e43cfed"
		creation_date = "2024-05-20"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "9b10bb3773011c4da44bf3a0f05b83079e4ad30f0b1eb2636a6025b927e03c7f"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { D0 4D E2 00 50 A0 E1 06 60 8F E0 08 00 00 0A 10 20 90 E5 18 30 90 E5 03 00 52 E1 01 40 D2 34 10 20 80 35 1F 00 00 3A 3B 01 00 EB 00 40 A0 E1 1C 00 00 EA 80 30 9F E5 38 40 80 E2 04 20 A0 E1 03 }

	condition:
		all of them
}
