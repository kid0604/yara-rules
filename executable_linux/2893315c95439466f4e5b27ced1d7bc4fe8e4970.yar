rule Linux_Hacktool_Flooder_678c1145
{
	meta:
		author = "Elastic Security"
		id = "678c1145-cc41-4e83-bc88-30f64da46dd3"
		fingerprint = "f4f66668b45f520bc107b7f671f8c7f42073d7ff28863e846a74fbd6cac03e87"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "559793b9cb5340478f76aaf5f81c8dbfbcfa826657713d5257dac3c496b243a6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { C8 48 BA AB AA AA AA AA AA AA AA 48 89 C8 48 F7 E2 48 C1 EA 05 48 }

	condition:
		all of them
}
