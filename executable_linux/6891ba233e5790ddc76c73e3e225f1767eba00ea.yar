rule Linux_Trojan_Mirai_b14f4c5d
{
	meta:
		author = "Elastic Security"
		id = "b14f4c5d-054f-46e6-9fa8-3588f1ef68b7"
		fingerprint = "a70d052918dd2fbc66db241da6438015130f0fb6929229bfe573546fe98da817"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint b14f4c5d"
		filetype = "executable"

	strings:
		$a = { 53 31 DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 15 66 8B 02 83 E9 02 25 FF FF 00 00 83 C2 02 01 C3 83 F9 01 77 EB 49 75 05 0F BE 02 01 C3 }

	condition:
		all of them
}
