rule MacOS_Trojan_Genieo_0d003634
{
	meta:
		author = "Elastic Security"
		id = "0d003634-8b17-4e26-b4a2-4bfce2e64dde"
		fingerprint = "6f38b7fc403184482449957aff51d54ac9ea431190c6f42c7a5420efbfdb8f7d"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Genieo"
		reference_sample = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Genieo variant 0d003634"
		filetype = "executable"

	strings:
		$a = { 75 69 6C 64 2F 41 6E 61 62 65 6C 50 61 63 6B 61 67 65 2F 62 75 69 6C 64 2F 73 }

	condition:
		all of them
}
