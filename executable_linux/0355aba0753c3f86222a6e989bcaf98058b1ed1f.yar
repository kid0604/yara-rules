rule Linux_Cryptominer_Generic_102d6f7c
{
	meta:
		author = "Elastic Security"
		id = "102d6f7c-0e77-4b23-9e84-756aba929d83"
		fingerprint = "037b1da31ffe66015c959af94d89eef2f7f846e1649e4415c31deaa81945aea9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "bd40c2fbf775e3c8cb4de4a1c7c02bc4bcfa5b459855b2e5f1a8ab40f2fb1f9e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 70 D2 AA C5 F9 EF D2 C5 F1 EF CB C5 E1 73 FB 04 C4 E3 79 DF }

	condition:
		all of them
}
