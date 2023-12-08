rule Linux_Trojan_Mirai_575f5bc8
{
	meta:
		author = "Elastic Security"
		id = "575f5bc8-b848-4db4-a99c-132d4d2bc8a4"
		fingerprint = "58e22a2acd002b07e1b1c546e8dfe9885d5dfd2092d4044630064078038e314f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 5A 56 5B 5B 55 42 44 5E 59 52 44 44 00 5E 73 5E 45 52 54 43 00 }

	condition:
		all of them
}
