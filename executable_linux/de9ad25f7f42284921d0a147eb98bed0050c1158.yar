rule Linux_Trojan_Mirai_a6a81f9c
{
	meta:
		author = "Elastic Security"
		id = "a6a81f9c-b43b-4ec3-8b0b-94c1cfee4f08"
		fingerprint = "e1ec5725b75e4bb3eefe34a17ced900a16af9329a07a99f18f88aaef2678bfc1"
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
		$a = { 41 57 00 54 43 50 00 47 52 45 00 4B 54 00 73 68 65 6C 6C 00 }

	condition:
		all of them
}
