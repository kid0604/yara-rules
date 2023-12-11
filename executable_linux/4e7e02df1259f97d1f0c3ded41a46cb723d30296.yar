rule Linux_Exploit_Local_47c64fb6
{
	meta:
		author = "Elastic Security"
		id = "47c64fb6-cfa6-4350-a41f-870b87116b32"
		fingerprint = "aa286440061fb31167f314111dde7c2f596357b41fb6a5656216892fee6bf56e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "0caa9035027ff88788e6b8e43bfc012a367a12148be809555c025942054a6360"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { F4 C6 00 FF 8B 45 F4 40 C6 00 25 8B 45 F4 83 C0 02 C7 00 08 00 }

	condition:
		all of them
}
