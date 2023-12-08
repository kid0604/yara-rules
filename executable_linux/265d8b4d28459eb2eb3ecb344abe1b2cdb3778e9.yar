rule Linux_Trojan_Mirai_fa3ad9d0
{
	meta:
		author = "Elastic Security"
		id = "fa3ad9d0-7c55-4621-90fc-6b154c44a67b"
		fingerprint = "fe93a3552b72b107f95cc5a7e59da64fe84d31df833bf36c81d8f31d8d79d7ca"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant fa3ad9d0"
		filetype = "executable"

	strings:
		$a = { CB 08 C1 CB 10 66 C1 CB 08 31 C9 8A 4F 14 D3 E8 01 D8 66 C1 }

	condition:
		all of them
}
