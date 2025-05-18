rule Windows_Trojan_Smokeloader_a01aa3ab
{
	meta:
		author = "Elastic Security"
		id = "a01aa3ab-b1d8-4cd1-8349-ff105e285f5d"
		fingerprint = "75b4fd2ace9aa87dab9fef950171a566bed8355ae4f7076755fa5293c68936a6"
		creation_date = "2024-08-27"
		last_modified = "2024-09-30"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "3a189a736cfdfbb1e3789326c35cecfa901a2adccc08c66c5de1cac8e4c1791b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Smokeloader"
		filetype = "executable"

	strings:
		$a = { 83 A6 43 0C 00 00 00 83 A6 3F 0C 00 00 00 45 33 C9 45 8D 41 04 33 D2 33 C9 }
		$b = { 42 0F B6 14 0C 41 8D 04 12 44 0F B6 D0 42 8A 04 14 42 88 04 0C 42 88 14 14 42 0F B6 }

	condition:
		any of them
}
