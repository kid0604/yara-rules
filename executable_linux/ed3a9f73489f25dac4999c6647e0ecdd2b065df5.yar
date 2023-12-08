rule Linux_Hacktool_Portscan_a40c7ef0
{
	meta:
		author = "Elastic Security"
		id = "a40c7ef0-627c-4965-b4d3-b05b79586170"
		fingerprint = "bf686c3c313936a144265cbf75850c8aee3af3ae36cb571050c7fceed385451d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Portscan"
		reference_sample = "c389c42bac5d4261dbca50c848f22c701df4c9a2c5877dc01e2eaa81300bdc29"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Portscan"
		filetype = "executable"

	strings:
		$a = { 54 50 44 00 52 65 73 70 6F 6E 73 65 20 77 61 73 20 4E 54 50 20 }

	condition:
		all of them
}
