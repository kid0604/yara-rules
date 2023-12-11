rule Linux_Trojan_Xorddos_2aef46a6
{
	meta:
		author = "Elastic Security"
		id = "2aef46a6-6daf-4f02-b1b4-e512cea12e53"
		fingerprint = "e583729c686b80e5da8e828a846cbd5218a4d787eff1fb2ce84a775ad67a1c4d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xorddos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }

	condition:
		all of them
}
