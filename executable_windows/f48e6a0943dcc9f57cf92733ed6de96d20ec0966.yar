rule Windows_Trojan_Emotet_18379a8d
{
	meta:
		author = "Elastic Security"
		id = "18379a8d-f1f2-49cc-8edf-58a3ba77efe7"
		fingerprint = "b7650b902a1a02029e28c88dd7ff91d841136005b0246ef4a08aaf70e57df9cc"
		creation_date = "2021-11-17"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Emotet"
		reference_sample = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Emotet with fingerprint 18379a8d"
		filetype = "executable"

	strings:
		$a = { 04 33 CB 88 0A 8B C1 C1 E8 08 8D 52 04 C1 E9 10 88 42 FD 88 }

	condition:
		all of them
}
