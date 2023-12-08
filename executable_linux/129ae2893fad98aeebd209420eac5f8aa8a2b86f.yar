rule Linux_Trojan_Mirai_7c88acbc
{
	meta:
		author = "Elastic Security"
		id = "7c88acbc-8b98-4508-ac53-ab8af858660d"
		fingerprint = "e2ef1c60e21f18e54694bcfc874094a941e5f61fa6144c5a0e44548dafa315be"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with ID 7c88acbc"
		filetype = "executable"

	strings:
		$a = "[Cobalt][%s][%s][%s][%s]"

	condition:
		all of them
}
