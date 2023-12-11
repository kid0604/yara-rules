rule Linux_Hacktool_Flooder_1cfa95dd
{
	meta:
		author = "Elastic Security"
		id = "1cfa95dd-e768-4071-9038-389c580741f9"
		fingerprint = "6ec21acb987464613830b3bbe1e2396093d269dae138c68fe77f35d88796001e"
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
		$a = { 83 7D EC 00 7E 0F 48 8B 45 F0 0F B6 00 0F B6 C0 48 01 C3 EB 10 }

	condition:
		all of them
}
