rule Linux_Trojan_Mirai_95e0056c
{
	meta:
		author = "Elastic Security"
		id = "95e0056c-bc07-42cf-89ab-6c0cde3ccc8a"
		fingerprint = "a2550fdd2625f85050cfe53159858207a79e8337412872aaa7b4627b13cb6c94"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "45f67d4c18abc1bad9a9cc6305983abf3234cd955d2177f1a72c146ced50a380"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 95e0056c"
		filetype = "executable"

	strings:
		$a = { 50 46 00 13 10 11 16 17 00 57 51 47 50 00 52 43 51 51 00 43 }

	condition:
		all of them
}
