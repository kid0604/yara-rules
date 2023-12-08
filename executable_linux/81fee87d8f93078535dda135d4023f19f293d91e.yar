rule Linux_Trojan_Generic_4f4cc3ea
{
	meta:
		author = "Elastic Security"
		id = "4f4cc3ea-a906-4fce-a482-d762ab8995b8"
		fingerprint = "d85dac2bd81925f5d8c90c11047c631c1046767cb6649cd266c3a143353b6c12"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "32e25641360dbfd50125c43754cd327cf024f1b3bfd75b617cdf8a17024e2da5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 4A 4E 49 20 55 4E 50 41 43 4B 20 44 45 58 20 53 54 41 52 54 20 }

	condition:
		all of them
}
