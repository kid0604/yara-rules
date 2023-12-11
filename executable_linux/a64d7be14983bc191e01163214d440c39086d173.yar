rule Linux_Exploit_Lotoor_ec339160
{
	meta:
		author = "Elastic Security"
		id = "ec339160-5f25-495c-8e48-4683ad2fcca0"
		fingerprint = "24a3630fd49860104c60c4f4d0ef03bd17c124383a0b5d027a06c7ca6cb9cbba"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "0002b469972f5c77a29e2a2719186059a3e96a6f4b1ef2d18a68fee3205ea0ba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 69 75 6D 3A 20 4C 69 6E 75 78 20 32 2E 58 20 73 }

	condition:
		all of them
}
