rule Windows_Ransomware_Hellokitty_d9391a1a
{
	meta:
		author = "Elastic Security"
		id = "d9391a1a-78d3-4ae6-8e45-630ceec8bade"
		fingerprint = "8779a926a237af0a966534931b60acd54f5d6d65063c070a3621ec604e280ff8"
		creation_date = "2021-05-03"
		last_modified = "2023-01-04"
		threat_name = "Windows.Ransomware.Hellokitty"
		reference_sample = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Hellokitty"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 04 85 DB 75 12 0F 10 45 D4 83 C7 10 0F 11 06 83 C6 10 83 }
		$a2 = { 89 45 F8 3B 5D F4 75 25 3B C6 75 21 6A FF FF 75 14 8B D1 83 }

	condition:
		any of them
}
