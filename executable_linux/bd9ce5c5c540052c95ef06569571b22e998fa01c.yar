rule Linux_Trojan_Mirai_d33095d4
{
	meta:
		author = "Elastic Security"
		id = "d33095d4-ea02-4588-9852-7493f6781bb4"
		fingerprint = "20c0faab6aef6e0f15fd34f9bd173547f3195c096eb34c4316144b19d2ab1dc4"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "72326a3a9160e9481dd6fc87159f7ebf8a358f52bf0c17fbc3df80217d032635"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint d33095d4"
		filetype = "executable"

	strings:
		$a = { 00 00 66 83 7C 24 54 FF 66 89 46 04 0F 85 CB }

	condition:
		all of them
}
