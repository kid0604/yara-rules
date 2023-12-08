rule Linux_Exploit_Lotoor_89671b03
{
	meta:
		author = "Elastic Security"
		id = "89671b03-5bd4-481b-9304-2655ea689c5f"
		fingerprint = "e8b9631e5d4d8db559615504cc3f6fbd8a81bfbdb9e570113f20d006c44c8a9c"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "001098473574cfac1edaca9f1180ab2005569e094be63186c45b48c18f880cf8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 62 65 6C 3A 20 4C 69 6E 75 78 20 3C 20 32 2E 36 }

	condition:
		all of them
}
