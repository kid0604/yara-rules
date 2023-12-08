rule MacOS_Trojan_Amcleaner_8ce3fea8
{
	meta:
		author = "Elastic Security"
		id = "8ce3fea8-3cc7-4c59-b07c-a6dda0bb6b85"
		fingerprint = "e156d3c7a55cae84481df644569d1c5760e016ddcc7fd05d0f88fa8f9f9ffdae"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Amcleaner"
		reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Amcleaner variant with ID 8ce3fea8"
		filetype = "executable"

	strings:
		$a = { 54 40 22 4E 53 54 61 62 6C 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6B 54 70 51 }

	condition:
		all of them
}
