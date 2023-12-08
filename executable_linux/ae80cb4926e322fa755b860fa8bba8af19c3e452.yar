rule Linux_Trojan_Mirai_ec591e81
{
	meta:
		author = "Elastic Security"
		id = "ec591e81-8594-4317-89b0-0fb4d43e14c1"
		fingerprint = "fe3d305202ca5376be7103d0b40f746fc26f8e442f8337a1e7c6d658b00fc4aa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "7d45a4a128c25f317020b5d042ab893e9875b6ff0ef17482b984f5b3fe87e451"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 22 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }

	condition:
		all of them
}
