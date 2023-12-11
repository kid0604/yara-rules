rule Linux_Trojan_Mirai_ae9d0fa6
{
	meta:
		author = "Elastic Security"
		id = "ae9d0fa6-be06-4656-9b13-8edfc0ee9e71"
		fingerprint = "ca2bf2771844bec95563800d19a35dd230413f8eff0bd44c8ab0b4c596f81bfc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai (ae9d0fa6) based on specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 83 EC 04 8A 44 24 18 8B 5C 24 14 88 44 24 03 8A 44 24 10 25 FF 00 }

	condition:
		all of them
}
