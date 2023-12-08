rule Windows_Trojan_Emotet_5528b3b0
{
	meta:
		author = "Elastic Security"
		id = "5528b3b0-d4cb-485e-bc0c-96415ec3a795"
		fingerprint = "717ed656d1bd4ba0e4dae8e47268e2c068dad3e3e883ff6da2f951d61f1be642"
		creation_date = "2021-11-17"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Emotet"
		reference_sample = "eeb13cd51faa7c23d9a40241d03beb239626fbf3efe1dbbfa3994fc10dea0827"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Emotet variant 5528b3b0"
		filetype = "executable"

	strings:
		$a = { 20 89 44 24 10 83 C2 02 01 74 24 10 01 7C 24 10 29 5C 24 10 66 }

	condition:
		all of them
}
