rule Linux_Trojan_Gafgyt_4f43b164
{
	meta:
		author = "Elastic Security"
		id = "4f43b164-686d-4b73-b532-45e2df992b33"
		fingerprint = "35a885850a06e7991c3a8612bbcdfc279b87e4ca549723192d3011a1e0a81640"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "f0fdb3de75f85e199766bbb39722865cac578cde754afa2d2f065ef028eec788"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 4f43b164"
		filetype = "executable"

	strings:
		$a = { 46 00 4B 49 4C 4C 53 55 42 00 4B 49 4C 4C 53 55 42 20 3C 73 }

	condition:
		all of them
}
