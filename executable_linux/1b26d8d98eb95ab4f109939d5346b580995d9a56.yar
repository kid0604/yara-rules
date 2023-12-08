rule Linux_Hacktool_Cleanlog_c2907d77
{
	meta:
		author = "Elastic Security"
		id = "c2907d77-6ea9-493f-a7b3-4a0795da0a1d"
		fingerprint = "131c71086c30ab22ca16b3020470561fa3d32c7ece9a8faa399a733e8894da30"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Cleanlog"
		reference_sample = "613ac236130ab1654f051d6f0661fa62414f3bef036ea4cc585b4b21a4bb9d2b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Cleanlog"
		filetype = "executable"

	strings:
		$a = { 89 E5 48 83 EC 10 89 7D FC 83 7D FC 00 7E 11 8B 45 FC BE 09 00 }

	condition:
		all of them
}
