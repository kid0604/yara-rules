rule Windows_Trojan_GhostPulse_caea316b
{
	meta:
		author = "Elastic Security"
		id = "caea316b-6896-40ca-87fc-1daae5ce8b9a"
		fingerprint = "71cc7e628aa6d189907cd320585b46cb73415ba60811c607951fb8398173a491"
		creation_date = "2024-10-10"
		last_modified = "2024-10-24"
		threat_name = "Windows.Trojan.GhostPulse"
		reference_sample = "454e898405a10ecc06b4243c25f86c855203722a4970dee4c4e1a4e8e75f5137"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan GhostPulse"
		filetype = "executable"

	strings:
		$a1 = { 48 83 EC 18 C7 04 24 00 00 00 00 8B 04 24 48 8B 4C 24 20 0F B7 04 41 85 C0 74 0A 8B 04 24 FF C0 89 04 24 EB E6 C7 44 24 08 00 00 00 00 8B 04 24 FF C8 8B C0 48 8B 4C 24 20 0F B7 04 41 83 F8 5C }

	condition:
		all of them
}
