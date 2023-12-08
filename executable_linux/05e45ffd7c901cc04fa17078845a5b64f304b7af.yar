rule Linux_Trojan_Tsunami_22646c0d
{
	meta:
		author = "Elastic Security"
		id = "22646c0d-785c-4cf2-b8c8-289189ae14d0"
		fingerprint = "0b1dce4e74536d4d06430aefd0127c740574dcc9a0e5ada42f3d51d97437720f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "20439a8fc21a94c194888725fbbb7a7fbeef5faf4b0f704559d89f1cd2e57d9d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { CB 01 00 00 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB }

	condition:
		all of them
}
