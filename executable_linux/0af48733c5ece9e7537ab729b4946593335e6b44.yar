rule Linux_Hacktool_Flooder_a2795a4c
{
	meta:
		author = "Elastic Security"
		id = "a2795a4c-16c0-4237-a014-3570d1edb287"
		fingerprint = "7c8bf248b159f3a140f10cd40d182fa84f334555b92306e6f44e746711b184cc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 48 8B 45 D8 66 89 50 04 48 8B 45 D8 0F B7 40 02 66 D1 E8 0F }

	condition:
		all of them
}
