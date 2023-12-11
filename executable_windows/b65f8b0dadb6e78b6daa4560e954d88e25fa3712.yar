rule Windows_Trojan_Sliver_1dd6d9c2
{
	meta:
		author = "Elastic Security"
		id = "1dd6d9c2-026e-4140-b804-b56e07c72ac2"
		fingerprint = "fb676adf8b9d10d1e151bfb2a6a7e132cff4e55c20f454201a4ece492902fc35"
		creation_date = "2023-05-10"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Sliver"
		reference_sample = "dc508a3e9ea093200acfc1ceebebb2b56686f4764fd8c94ab8c58eec7ee85c8b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan Sliver (1dd6d9c2)"
		filetype = "executable"

	strings:
		$a1 = { B7 11 49 89 DB C1 EB 10 41 01 DA 66 45 89 11 4C 89 DB EB B6 4D 8D }
		$a2 = { 36 2E 33 20 62 75 69 6C 48 39 }

	condition:
		all of them
}
