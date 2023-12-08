rule Linux_Trojan_Mirai_0bfc17bd
{
	meta:
		author = "Elastic Security"
		id = "0bfc17bd-49bb-4721-9653-0920b631b1de"
		fingerprint = "d67e4e12e74cbd31037fae52cf7bad8d8d5b4240d79449fa1ebf9a271af008e1"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "1cdd94f2a1cb2b93134646c171d947e325a498f7a13db021e88c05a4cbb68903"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 0bfc17bd"
		filetype = "executable"

	strings:
		$a = { 54 24 64 0F CD 48 8D 14 52 41 0F B6 4C D7 14 D3 E8 01 C5 83 7C 24 }

	condition:
		all of them
}
