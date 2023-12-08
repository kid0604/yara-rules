rule Windows_Trojan_Matanbuchus_c7811ccc
{
	meta:
		author = "Elastic Security"
		id = "c7811ccc-5d8d-4bc8-a630-ac3282bb207e"
		fingerprint = "05f209a24d9eb2be7fa50444d8271b6f147027291f55a352ac3af5e9b3207010"
		creation_date = "2022-03-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Matanbuchus"
		reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Matanbuchus"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 83 EC 08 53 56 0F 57 C0 66 0F 13 45 F8 EB ?? 8B 45 F8 83 C0 01 8B 4D FC 83 D1 00 89 45 F8 89 4D FC 8B 55 FC 3B 55 10 77 ?? 72 ?? 8B 45 F8 3B 45 0C 73 ?? 6A 00 6A 08 8B 4D FC 51 8B 55 F8 52 E8 ?? ?? ?? ?? 6A 00 6A 08 52 50 E8 ?? ?? ?? ?? 8B C8 8B 45 14 8B 55 18 E8 ?? ?? ?? ?? 0F BE F0 6A 00 6A 01 8B 55 FC 52 8B 45 F8 50 E8 ?? ?? ?? ?? 8B 4D 08 0F BE 1C 01 33 DE 6A 00 6A 01 8B 55 FC 52 8B 45 F8 50 E8 ?? ?? ?? ?? 8B 4D 08 88 1C 01 E9 ?? ?? ?? ?? 5E 5B 8B E5 5D C2 14 00 }

	condition:
		all of them
}
