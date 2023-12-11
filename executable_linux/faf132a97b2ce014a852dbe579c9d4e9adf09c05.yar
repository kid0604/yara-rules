rule Linux_Trojan_Gafgyt_d4227dbf
{
	meta:
		author = "Elastic Security"
		id = "d4227dbf-6ab4-4637-a6ba-0e604acaafb4"
		fingerprint = "58c4b1d4d167876b64cfa10f609911a80284180e4db093917fea16fae8ccd4e3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 }

	condition:
		all of them
}
