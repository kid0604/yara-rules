rule Linux_Trojan_Mirai_3278f1b8
{
	meta:
		author = "Elastic Security"
		id = "3278f1b8-f208-42c8-a851-d22413f74dea"
		fingerprint = "7e9fc284c9c920ac2752911d6aacbc3c2bf1b053aa35c22d83bab0089290778d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 3278f1b8"
		filetype = "executable"

	strings:
		$a = { D2 0F B6 C3 C1 E0 10 0F B6 C9 C1 E2 18 09 C2 0F B6 44 24 40 C1 }

	condition:
		all of them
}
