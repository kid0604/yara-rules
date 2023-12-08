rule Linux_Trojan_Gafgyt_9e9530a7
{
	meta:
		author = "Elastic Security"
		id = "9e9530a7-ad4d-4a44-b764-437b7621052f"
		fingerprint = "d6ad6512051e87c8c35dc168d82edd071b122d026dce21d39b9782b3d6a01e50"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 9e9530a7"
		filetype = "executable"

	strings:
		$a = { F6 48 63 FF B8 36 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 }

	condition:
		all of them
}
