rule Windows_Generic_Threat_85c73807
{
	meta:
		author = "Elastic Security"
		id = "85c73807-4181-4d4a-ba51-6ed923121486"
		fingerprint = "8b63723aa1b89149c360048900a18e25a0a615f50cec1aaadca2578684f5bcb2"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "7f560a22c1f7511518656ac30350229f7a6847d26e1b3857e283f7dcee2604a0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 C6 86 18 01 00 00 00 8B C3 E8 15 01 00 00 84 C0 75 0E 8B 55 FC 8B C6 8B CF E8 45 F8 FF FF EB 0F 56 57 8B FE 8B F3 B9 47 00 00 00 F3 A5 5F 5E }

	condition:
		all of them
}
