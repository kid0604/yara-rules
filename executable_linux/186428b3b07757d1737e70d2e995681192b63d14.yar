rule Linux_Hacktool_Cleanlog_3eb725d1
{
	meta:
		author = "Elastic Security"
		id = "3eb725d1-24de-427a-b6ed-3ca03c0716df"
		fingerprint = "54d3c59ba5ca16fbe99a4629f4fe7464d13f781985a7f35d05604165f9284483"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Cleanlog"
		reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Cleanlog"
		filetype = "executable"

	strings:
		$a = { 45 E0 83 45 C0 01 EB 11 83 45 DC 01 EB 0B 83 45 D8 01 EB 05 83 45 }

	condition:
		all of them
}
