rule Linux_Hacktool_Cleanlog_400b7595
{
	meta:
		author = "Elastic Security"
		id = "400b7595-c3c4-4999-b3b9-dcfe9b5df3f6"
		fingerprint = "4423f1597b199046bfc87923e3e229520daa2da68c4c4a3ac69127ace518f19a"
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
		$a = { 72 20 65 6E 74 72 79 20 28 64 65 66 61 75 6C 74 3A 20 31 73 74 20 }

	condition:
		all of them
}
