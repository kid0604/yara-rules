rule Linux_Trojan_Mirai_e0cf29e2
{
	meta:
		author = "Elastic Security"
		id = "e0cf29e2-88d7-4aa4-b60a-c24626f2b246"
		fingerprint = "3f124c3c9f124264dfbbcca1e4b4d7cfcf3274170d4bf8966b6559045873948f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with fingerprint e0cf29e2"
		filetype = "executable"

	strings:
		$a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C2 83 FE 01 }

	condition:
		all of them
}
