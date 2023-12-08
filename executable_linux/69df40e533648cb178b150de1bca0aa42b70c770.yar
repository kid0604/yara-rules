rule Linux_Trojan_Generic_5420d3e7
{
	meta:
		author = "Elastic Security"
		id = "5420d3e7-012f-4ce0-bb13-9e5221efa73e"
		fingerprint = "e81615b5756c2789b9be8fb10420461d5260914e16ba320cbab552d654bbbd8a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "103b8fced0aebd73cb8ba9eff1a55e6b6fa13bb0a099c9234521f298ee8d2f9f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 63 00 5F 5A 4E 34 41 52 43 34 37 65 6E 63 72 79 70 74 45 50 63 }

	condition:
		all of them
}
