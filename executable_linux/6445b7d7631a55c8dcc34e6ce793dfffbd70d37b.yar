rule Linux_Trojan_Gafgyt_46eec778
{
	meta:
		author = "Elastic Security"
		id = "46eec778-7342-4ef7-adac-35bc0cdb9867"
		fingerprint = "2602371a40171870b1cf024f262e95a2853de53de39c3a6cd3de811e81dd3518"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { C0 01 45 F8 48 83 45 E8 02 83 6D C8 02 83 7D C8 01 7F E4 83 7D }

	condition:
		all of them
}
