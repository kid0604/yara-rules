rule Linux_Hacktool_Flooder_51ef0659
{
	meta:
		author = "Elastic Security"
		id = "51ef0659-2691-4558-bff8-fce614f10ab9"
		fingerprint = "41f517a19a3c4dc412200b683f4902a656f3dcfdead8b8292e309413577c3850"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "b7a2bc75dd9c44c38b2a6e4e7e579142ece92a75b8a3f815940c5aa31470be2b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { E0 03 48 89 45 B0 8B 45 9C 48 63 D0 48 83 EA 01 48 89 55 B8 48 }

	condition:
		all of them
}
