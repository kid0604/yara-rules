rule Linux_Trojan_Rekoobe_e75472fa
{
	meta:
		author = "Elastic Security"
		id = "e75472fa-0263-4a47-a3bd-2d1bb14df177"
		fingerprint = "4e7605685ba7ba53afeafdef7e46bdca76109bd4d8b9116a93c301edeff606ee"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "8d2a9e363752839a09001a9e3044ab7919daffd9d9aee42d936bc97394164a88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Rekoobe"
		filetype = "executable"

	strings:
		$a = { 00 00 00 83 F8 01 74 1F 89 D0 48 8B 4C 24 08 64 48 33 0C 25 28 00 }

	condition:
		all of them
}
