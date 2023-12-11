rule Linux_Trojan_Gafgyt_4d81ad42
{
	meta:
		author = "Elastic Security"
		id = "4d81ad42-bf08-48a9-9a93-85cb491257b3"
		fingerprint = "f285683c3b145990e1b6d31d3c9d09177ebf76f183d0fa336e8df3dbcba24366"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "3021a861e6f03df3e7e3919e6255bdae6e48163b9a8ba4f1a5c5dced3e3e368b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with ID 4d81ad42"
		filetype = "executable"

	strings:
		$a = { 0F 44 C8 07 0B BF F1 1B 7E 83 CD FF 31 DB 2E 22 }

	condition:
		all of them
}
