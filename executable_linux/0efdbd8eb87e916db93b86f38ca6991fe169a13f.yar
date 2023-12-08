rule Linux_Trojan_Gafgyt_5008aee6
{
	meta:
		author = "Elastic Security"
		id = "5008aee6-3866-4f0a-89bf-bde740baee5c"
		fingerprint = "6876a6c1333993c4349e459d4d13c11be1b0f78311274c0f778e65d0fabeeaa7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "b32cd71fcfda0a2fcddad49d8c5ba8d4d68867b2ff2cb3b49d1a0e358346620c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 5008aee6"
		filetype = "executable"

	strings:
		$a = { 50 16 B4 87 58 83 00 21 84 51 FD 13 4E 79 28 57 C3 8B 30 55 }

	condition:
		all of them
}
