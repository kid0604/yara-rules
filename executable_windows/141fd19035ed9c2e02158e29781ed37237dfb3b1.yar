rule Windows_Trojan_Havoc_88053562
{
	meta:
		author = "Elastic Security"
		id = "88053562-ae19-44fe-8aaf-d6b9687d6b80"
		fingerprint = "818011b7972ab71cbfe07ec2266f504ba0ec7df30136e414d15366aa68ad5b8a"
		creation_date = "2024-01-04"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.Havoc"
		reference_sample = "2f0b59f8220edd0d34fba92905faf0b51aead95d53be8b5f022eed7e21bdb4af"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Havoc"
		filetype = "executable"

	strings:
		$a = { 48 81 EC F8 04 00 00 48 8D 7C 24 78 44 89 8C 24 58 05 00 00 48 8B AC 24 60 05 00 00 4C 8D 6C 24 78 F3 AB B9 59 00 00 00 48 C7 44 24 70 00 00 00 00 C7 44 24 78 68 00 00 00 C7 84 24 B4 00 00 00 }

	condition:
		all of them
}
