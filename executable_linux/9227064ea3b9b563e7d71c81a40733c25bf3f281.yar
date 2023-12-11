rule Linux_Trojan_Mirai_b548632d
{
	meta:
		author = "Elastic Security"
		id = "b548632d-7916-444a-aa68-4b3e38251905"
		fingerprint = "8b355e9c1150d43f52e6e9e052eda87ba158041f7b645f4f67c32dd549c09f28"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "639d9d6da22e84fb6b6fc676a1c4cfd74a8ed546ce8661500ab2ef971242df07"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant b548632d"
		filetype = "executable"

	strings:
		$a = { 00 0B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }

	condition:
		all of them
}
