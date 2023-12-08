rule Windows_Trojan_Matanbuchus_58a61aaa
{
	meta:
		author = "Elastic Security"
		id = "58a61aaa-51b2-47f2-ab32-2e639957b2d5"
		fingerprint = "332794db0ed7488e939a91594d2100ee013a7f8f91afc085e15f06fc69098ad5"
		creation_date = "2022-03-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Matanbuchus"
		reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan Matanbuchus"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 83 EC 08 53 56 0F 57 C0 66 0F 13 45 F8 EB ?? 8B 45 F8 83 C0 01 8B 4D FC 83 D1 00 89 45 F8 89 4D FC 8B 55 FC 3B 55 }

	condition:
		all of them
}
