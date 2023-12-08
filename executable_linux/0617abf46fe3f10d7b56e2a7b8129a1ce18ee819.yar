rule Linux_Trojan_Mirai_fa48b592
{
	meta:
		author = "Elastic Security"
		id = "fa48b592-8d80-45af-a3e4-232695b8f5dd"
		fingerprint = "8838d2752b310dbf7d12f6cf023244aaff4fdf5b55cf1e3b71843210df0fcf88"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "c9e33befeec133720b3ba40bb3cd7f636aad80f72f324c5fe65ac7af271c49ee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 31 C0 BA 01 00 00 00 B9 01 00 00 00 03 04 24 89 D7 31 D2 F7 F7 0F }

	condition:
		all of them
}
