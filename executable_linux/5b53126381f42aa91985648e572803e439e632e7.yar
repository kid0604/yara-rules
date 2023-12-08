rule Linux_Trojan_Gafgyt_e4a1982b
{
	meta:
		author = "Elastic Security"
		id = "e4a1982b-928a-4da5-b497-cedc1d26e845"
		fingerprint = "d9f852c28433128b0fd330bee35f7bd4aada5226e9ca865fe5cd8cca52b2a622"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt based on specific characteristics"
		filetype = "executable"

	strings:
		$a = { 8B 45 EC F7 D0 21 D0 33 45 FC C9 C3 55 48 89 E5 48 83 EC 30 48 89 }

	condition:
		all of them
}
