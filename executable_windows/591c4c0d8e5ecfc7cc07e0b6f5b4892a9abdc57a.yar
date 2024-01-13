rule Windows_Trojan_Afdk_c952fcfa
{
	meta:
		author = "Elastic Security"
		id = "c952fcfa-75e1-4880-a4e3-1e4cc89c160f"
		fingerprint = "577b2f82944711a51e52eb35a0eaf17379576ae151dd820d8b442e8fed8a5373"
		creation_date = "2023-12-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.Afdk"
		reference_sample = "6723a9489e7cfb5e2d37ff9160d55cda065f06907122d73764849808018eb7a0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Afdk"
		filetype = "executable"

	strings:
		$a = { 55 8B EC 51 51 83 65 F8 00 8D 45 F8 83 65 FC 00 50 E8 80 FF FF FF 59 85 C0 75 2B 8B 4D 08 8B 55 F8 8B 45 FC 89 41 04 8D 45 F8 89 11 83 CA 1F 50 89 55 F8 E8 7B FF FF FF 59 85 C0 75 09 E8 DA 98 }

	condition:
		all of them
}
