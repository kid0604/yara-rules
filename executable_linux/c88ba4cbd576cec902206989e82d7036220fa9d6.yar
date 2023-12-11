rule Linux_Hacktool_Flooder_b1ca2abd
{
	meta:
		author = "Elastic Security"
		id = "b1ca2abd-b8ab-435d-85b6-a1c93212e492"
		fingerprint = "214c9dedf34b2c8502c6ef14aff5727ac5a2941e1a8278a48d34fea14d584a1a"
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
		$a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 B0 C7 45 AC 14 00 }

	condition:
		all of them
}
