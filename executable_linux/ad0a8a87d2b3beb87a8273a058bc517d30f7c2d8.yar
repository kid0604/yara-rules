rule Linux_Trojan_Gafgyt_eb96cc26
{
	meta:
		author = "Elastic Security"
		id = "eb96cc26-e6d6-4388-a5da-2501e6e2ea32"
		fingerprint = "73967a3499d5dce61735aa2d352c1db48bb1d965b2934bb924209d729b5eb162"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "440318179ba2419cfa34ea199b49ee6bdecd076883d26329bbca6dca9d39c500"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 49 6E 66 6F 3A 20 0A 00 5E 6A 02 5F 6A 01 58 0F 05 6A 7F 5F }

	condition:
		all of them
}
