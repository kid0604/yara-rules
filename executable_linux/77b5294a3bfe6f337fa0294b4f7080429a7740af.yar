rule Linux_Trojan_Ngioweb_66c465a0
{
	meta:
		author = "Elastic Security"
		id = "66c465a0-821d-43ea-82f5-fe787720bfbf"
		fingerprint = "e26071afff71506236b261a44e8f1903d348dd33b95597458649f377710492f4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb"
		filetype = "executable"

	strings:
		$a = { 75 E6 B2 07 FE C0 EB DE 83 EC 10 6A 00 6A 00 6A 00 6A 00 FF 74 }

	condition:
		all of them
}
