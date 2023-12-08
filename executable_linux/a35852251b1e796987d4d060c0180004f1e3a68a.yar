rule Linux_Hacktool_Flooder_a9e8a90f
{
	meta:
		author = "Elastic Security"
		id = "a9e8a90f-5d95-4f4e-a9e0-c595be3729dd"
		fingerprint = "a06bbcbc09e5e44447b458d302c47e4f18438be8d57687700cb4bf3f3630fba8"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "0558cf8cab0ba1515b3b69ac32975e5e18d754874e7a54d19098e7240ebf44e4"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 45 D8 48 89 45 F0 66 C7 45 EE 00 00 EB 19 48 8B 45 F0 48 8D }

	condition:
		all of them
}
