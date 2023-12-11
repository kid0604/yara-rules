rule Linux_Trojan_Mirai_cc93863b
{
	meta:
		author = "Elastic Security"
		id = "cc93863b-1050-40ba-9d02-5ec9ce6a3a28"
		fingerprint = "f3ecd30f0b511a8e92cfa642409d559e7612c3f57a1659ca46c77aca809a00ac"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { C3 57 8B 44 24 0C 8B 4C 24 10 8B 7C 24 08 F3 AA 8B 44 24 08 }

	condition:
		all of them
}
