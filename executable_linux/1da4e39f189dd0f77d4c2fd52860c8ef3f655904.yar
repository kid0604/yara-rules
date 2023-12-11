rule Linux_Trojan_Xorddos_e41143e1
{
	meta:
		author = "Elastic Security"
		id = "e41143e1-52d9-45c7-b19f-a5475b18a510"
		fingerprint = "f621a2e8c289772990093762f371bb6d5736085695881e728a0d2c013c2ad1d4"
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
		$a = { 73 1E 80 3C 06 00 8D 14 30 8D 4C 37 FF 74 0D EB 36 0F B6 42 01 83 }

	condition:
		all of them
}
