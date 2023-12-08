rule Linux_Hacktool_Flooder_b93655d3
{
	meta:
		author = "Elastic Security"
		id = "b93655d3-1d3f-42f4-a47f-a69624e90da5"
		fingerprint = "55119467cb5f9789b74064e63c1e7d905457b54f6e4da1a83c498313d6c90b5b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { C0 49 89 C5 74 45 45 85 F6 7E 28 48 89 C3 41 8D 46 FF 4D 8D 64 }

	condition:
		all of them
}
