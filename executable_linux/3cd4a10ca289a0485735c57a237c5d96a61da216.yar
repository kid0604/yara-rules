rule Linux_Hacktool_Flooder_761ad88e
{
	meta:
		author = "Elastic Security"
		id = "761ad88e-1667-4253-81f6-52c92e0ccd68"
		fingerprint = "14e701abdef422dcde869a2278ec6e1fb7889dcd9681a224b29a00bcb365e391"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 2E 31 36 38 2E 33 2E 31 30 30 00 43 6F 75 6C 64 20 6E 6F 74 }

	condition:
		all of them
}
