rule Linux_Trojan_Merlin_c6097296
{
	meta:
		author = "Elastic Security"
		id = "c6097296-c518-4541-99b2-e2f6d3e4610b"
		fingerprint = "8496ec66e276304108184db36add64936500f1f0dd74120e03b78c64ac7b5ba1"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Merlin"
		reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Merlin"
		filetype = "executable"

	strings:
		$a = { 54 24 38 48 89 5C 24 48 48 85 C9 75 62 48 85 D2 75 30 48 89 9C 24 C8 00 }

	condition:
		all of them
}
