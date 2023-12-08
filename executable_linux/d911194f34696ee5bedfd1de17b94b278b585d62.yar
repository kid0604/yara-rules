rule Linux_Trojan_Mirai_268aac0b
{
	meta:
		author = "Elastic Security"
		id = "268aac0b-c5c7-4035-8381-4e182de91e32"
		fingerprint = "9c581721bf82af7dc6482a2c41af5fb3404e01c82545c7b2b29230f707014781"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 268aac0b"
		filetype = "executable"

	strings:
		$a = { 24 18 0F B7 44 24 20 8B 54 24 1C 83 F9 01 8B 7E 0C 89 04 24 8B }

	condition:
		all of them
}
