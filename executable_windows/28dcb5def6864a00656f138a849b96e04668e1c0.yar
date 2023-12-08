rule Windows_Trojan_BruteRatel_4110d879
{
	meta:
		author = "Elastic Security"
		id = "4110d879-8d36-4004-858d-e62400948920"
		fingerprint = "64d7a121961108d17e03fa767bd5bc194c8654dfa18b3b2f38cf6c95a711f794"
		creation_date = "2023-05-10"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.BruteRatel"
		reference_sample = "e0fbbc548fdb9da83a72ddc1040463e37ab6b8b544bf0d2b206bfff352175afe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BruteRatel"
		filetype = "executable"

	strings:
		$a1 = { 04 01 75 E2 48 83 C0 01 44 0F B6 04 02 45 84 C0 75 EC 48 89 }
		$a2 = { C8 48 83 E9 20 44 0F B6 40 E0 41 80 F8 E9 74 0B 44 0F B6 49 03 41 80 }

	condition:
		all of them
}
