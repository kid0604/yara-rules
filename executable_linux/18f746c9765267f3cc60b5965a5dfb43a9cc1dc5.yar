rule Linux_Trojan_Gafgyt_620087b9
{
	meta:
		author = "Elastic Security"
		id = "620087b9-c87d-4752-89e8-ca1c16486b28"
		fingerprint = "06cd7e6eb62352ec2ccb9ed48e58c0583c02fefd137cd048d053ab30b5330307"
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
		$a = { 48 89 D8 48 83 C8 01 EB 04 48 8B 76 10 48 3B 46 08 72 F6 48 8B }

	condition:
		all of them
}
