rule Linux_Trojan_Mirai_6f021787
{
	meta:
		author = "Elastic Security"
		id = "6f021787-9c2d-4536-bd90-5230c85a8718"
		fingerprint = "33ba39b77e55b1a2624e7846e06b2a820de9a8a581a7eec57e35b3a1636b8b0d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "88183d71359c16d91a3252085ad5a270ad3e196fe431e3019b0810ecfd85ae10"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 6f021787"
		filetype = "executable"

	strings:
		$a = { 55 D4 66 89 14 01 0F B6 45 D0 48 63 D0 48 89 D0 48 01 C0 48 }

	condition:
		all of them
}
