rule Linux_Trojan_Gafgyt_33b4111a
{
	meta:
		author = "Elastic Security"
		id = "33b4111a-e59e-48db-9d74-34ca44fcd9f5"
		fingerprint = "9c3b63b9a0f54006bae12abcefdb518904a85f78be573f0780f0a265b12d2d6e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint 33b4111a"
		filetype = "executable"

	strings:
		$a = { C1 83 E1 0F 74 1A B8 10 00 00 00 48 29 C8 48 8D 0C 02 48 89 DA 48 }

	condition:
		all of them
}
