rule Windows_Trojan_GhostPulse_a1311f49
{
	meta:
		author = "Elastic Security"
		id = "a1311f49-65a7-4136-a5ab-28cf4de4d40f"
		fingerprint = "e07a8152ab75624aa8dd0a8301d690a6a4bdd3b0e069699632541fb6a32e419b"
		creation_date = "2023-10-06"
		last_modified = "2023-10-26"
		threat_name = "Windows.Trojan.GhostPulse"
		reference_sample = "0175448655e593aa299278d5f11b81f2af76638859e104975bdb5d30af5c0c11"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan GhostPulse"
		filetype = "executable"

	strings:
		$a1 = { 0F BE 00 48 0F BE C0 85 C0 74 0D B8 01 00 00 00 03 45 00 89 45 00 EB E1 8B 45 00 48 8D 65 10 5D C3 }
		$a2 = { 88 4C 24 08 48 83 EC 18 0F B6 44 24 20 88 04 24 0F BE 44 24 20 83 F8 41 7C 13 0F BE 04 24 83 F8 5A 7F 0A 0F BE 04 24 83 C0 20 88 04 24 }

	condition:
		any of them
}
