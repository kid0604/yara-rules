rule Linux_Trojan_Mirai_3b9675fd
{
	meta:
		author = "Elastic Security"
		id = "3b9675fd-1fa1-4e15-9472-64cb93315d63"
		fingerprint = "40a154bafa72c5aa0c085ac2b92b5777d1acecfd28d28b15c7229ba5c59435f2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "4ec4bc88156bd51451fdaf0550c21c799c6adacbfc654c8ec634ebca3383bd66"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant"
		filetype = "executable"

	strings:
		$a = { 78 10 85 C9 75 65 48 8B 8C 24 A0 00 00 00 48 89 48 10 0F B6 4C }

	condition:
		all of them
}
