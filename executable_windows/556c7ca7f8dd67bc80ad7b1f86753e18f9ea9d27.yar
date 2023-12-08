rule Windows_Trojan_Vidar_32fea8da
{
	meta:
		author = "Elastic Security"
		id = "32fea8da-b381-459c-8bf4-696388b8edcc"
		fingerprint = "ebcced7b2924cc9cfe9ed5b5f84a8959e866a984f2b5b6e1ec5b1dd096960325"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Vidar"
		reference_sample = "6f5c24fc5af2085233c96159402cec9128100c221cb6cb0d1c005ced7225e211"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Vidar"
		filetype = "executable"

	strings:
		$a1 = { 4F 4B 58 20 57 65 62 33 20 57 61 6C 6C 65 74 }
		$a2 = { 8B E5 5D C3 5E B8 03 00 00 00 5B 8B E5 5D C3 5E B8 08 00 00 }
		$a3 = { 83 79 04 00 8B DE 74 08 8B 19 85 DB 74 62 03 D8 8B 03 85 C0 }

	condition:
		all of them
}
