rule Linux_Trojan_Mirai_c5430ff9
{
	meta:
		author = "Elastic Security"
		id = "c5430ff9-af40-4653-94c3-4651a5e9331e"
		fingerprint = "a19dcb00fc5553d41978184cc53ef93c36eb9541ea19c6c50496b4e346aaf240"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "5676773882a84d0efc220dd7595c4594bc824cbe3eeddfadc00ac3c8e899aa77"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 00 00 00 FC F3 A6 0F 97 C2 0F 92 C0 38 C2 75 29 83 EC 08 8B }

	condition:
		all of them
}
