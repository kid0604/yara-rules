rule Linux_Exploit_Lotoor_f8e9f93c
{
	meta:
		author = "Elastic Security"
		id = "f8e9f93c-78ad-4ca5-a210-e62072e6f8c8"
		fingerprint = "bdf87b68d1101cd3fcbc505de0d2e9b2aed9535aaafa9f746f7a3c4fba03b464"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "50a6d546d4c45dc33c5ece3c09dbc850b469b9b8deeb7181a45ba84459cb24c9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 61 ?? 3A 20 4C 69 6E 75 78 20 32 2E 36 2E 33 }

	condition:
		all of them
}
