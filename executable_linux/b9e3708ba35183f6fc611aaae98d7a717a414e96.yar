rule Linux_Trojan_Gafgyt_a0a4de11
{
	meta:
		author = "Elastic Security"
		id = "a0a4de11-fe65-449f-a990-ad5f18ac66f0"
		fingerprint = "891cfc6a4c38fb257ada29050e0047bd1301e8f0a6a1a919685b1fcc2960b047"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 42 0D 83 C8 10 88 42 0D 48 8B 55 D8 0F B6 42 0D 83 C8 08 88 }

	condition:
		all of them
}
