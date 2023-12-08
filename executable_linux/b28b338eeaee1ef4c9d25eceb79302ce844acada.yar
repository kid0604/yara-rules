rule Linux_Trojan_Mirai_449937aa
{
	meta:
		author = "Elastic Security"
		id = "449937aa-682a-4906-89ab-80d7127e461e"
		fingerprint = "cf2c6b86830099f039b41aeaafbffedfb8294a1124c499e99a11f48a06cd1dfd"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "6f27766534445cffb097c7c52db1fca53b2210c1b10b75594f77c34dc8b994fe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 00 00 5B 72 65 73 6F 6C 76 5D 20 46 6F 75 6E 64 20 49 50 20 }

	condition:
		all of them
}
