rule Linux_Generic_Threat_75813ab2
{
	meta:
		author = "Elastic Security"
		id = "75813ab2-47f5-40ad-b512-9aa081abdc03"
		fingerprint = "e5b985f588cf6d1580b8e5dc85350fd0e1ca22ca810b1eca8d2bed774237c930"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "5819eb73254fd2a698eb71bd738cf3df7beb65e8fb5e866151e8135865e3fd9a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 5B 2B 5D 20 6D 6D 61 70 3A 20 30 78 25 6C 78 20 2E 2E 20 30 78 25 6C 78 }
		$a2 = { 5B 2B 5D 20 70 61 67 65 3A 20 30 78 25 6C 78 }

	condition:
		all of them
}
