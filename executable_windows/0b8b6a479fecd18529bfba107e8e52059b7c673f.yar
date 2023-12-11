rule Windows_Trojan_Generic_ae824b13 : ref1296
{
	meta:
		author = "Elastic Security"
		id = "ae824b13-eaae-49e6-a965-ff10379f3c41"
		fingerprint = "8658996385aac060ebe9eab45bbea8b05b9008926bb3085e5589784473bc3086"
		creation_date = "2022-02-03"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Generic"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic ae824b13"
		filetype = "executable"

	strings:
		$a1 = { 31 31 34 2E 31 31 34 2E 31 31 34 2E 31 31 34 }
		$a2 = { 69 6E 66 6F 40 63 69 61 2E 6F 72 67 30 }
		$a3 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 30 2E 30 2E 32 36 36 31 2E 39 34 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
		$a4 = { 75 73 65 72 25 33 64 61 64 6D 69 6E 25 32 36 70 61 73 73 77 6F 72 64 25 33 64 64 65 66 61 75 6C 74 25 34 30 72 6F 6F 74 }

	condition:
		3 of them
}
