rule Linux_Trojan_Mirai_a39dfaa7
{
	meta:
		author = "Elastic Security"
		id = "a39dfaa7-7d2c-4d40-bea5-bbebad522fa4"
		fingerprint = "95d12cb127c088d55fb0090a1cb0af8e0a02944ff56fd18bcb0834b148c17ad7"
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
		$a = { 00 6C 72 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }

	condition:
		all of them
}
