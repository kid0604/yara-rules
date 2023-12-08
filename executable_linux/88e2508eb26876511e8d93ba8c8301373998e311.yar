rule Linux_Trojan_Mirai_5f7b67b8
{
	meta:
		author = "Elastic Security"
		id = "5f7b67b8-3d7b-48a4-8f03-b6f2c92be92e"
		fingerprint = "6cb5fb0b7c132e9c11ac72da43278025b60810ea3733c9c6d6ca966163185940"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux Trojan Mirai variant 5f7b67b8"
		filetype = "executable"

	strings:
		$a = { 89 38 83 CF FF 89 F8 5A 59 5F C3 57 56 83 EC 04 8B 7C 24 10 8B 4C }

	condition:
		all of them
}
