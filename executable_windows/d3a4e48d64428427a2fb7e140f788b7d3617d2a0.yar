rule Windows_Trojan_Guloader_2f1e44c8
{
	meta:
		author = "Elastic Security"
		id = "2f1e44c8-f269-4cd6-a516-8d9282ddcfbc"
		fingerprint = "b00255f8d7ce460ffc778e96f6101db753e8992d36ee75a25b48e32ac7817c58"
		creation_date = "2023-10-30"
		last_modified = "2023-11-02"
		threat_name = "Windows.Trojan.Guloader"
		reference_sample = "6ae7089aa6beaa09b1c3aa3ecf28a884d8ca84f780aab39902223721493b1f99"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Guloader variant with specific strings"
		filetype = "executable"

	strings:
		$djb2_str_compare = { 83 C0 08 83 3C 04 00 0F 84 [4] 39 14 04 75 }
		$check_exception = { 8B 45 ?? 8B 00 38 EC 8B 58 ?? 84 FD 81 38 05 00 00 C0 }
		$parse_mem = { 18 00 10 00 00 83 C0 18 50 83 E8 04 81 00 00 10 00 00 50 }
		$hw_bp = { 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [7] 39 48 18 }
		$scan_protection = { 39 ?? 14 8B [5] 0F 84 }

	condition:
		2 of them
}
