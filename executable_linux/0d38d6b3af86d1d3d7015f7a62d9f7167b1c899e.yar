rule Linux_Trojan_Mirai_a68e498c
{
	meta:
		author = "Elastic Security"
		id = "a68e498c-0768-4321-ab65-42dd6ef85323"
		fingerprint = "951c9dfcba531e5112c872395f6c144c4bc8b71c666d2c7d9d8574a23c163883"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 10 39 D0 7E 25 8B 4C 24 38 01 D1 8A 11 8D 42 9F 3C 19 77 05 8D }

	condition:
		all of them
}
