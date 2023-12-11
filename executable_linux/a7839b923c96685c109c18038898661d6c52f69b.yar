rule Linux_Trojan_Mirai_1e0c5ce0
{
	meta:
		author = "Elastic Security"
		id = "1e0c5ce0-3b76-4da4-8bed-2e5036b6ce79"
		fingerprint = "8e45538b59f9c9b8bc49661069044900c8199e487714c715c1b1f970fd528e3b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "5b1f95840caebf9721bf318126be27085ec08cf7881ec64a884211a934351c2d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 1e0c5ce0"
		filetype = "executable"

	strings:
		$a = { 4C 24 54 31 F6 41 B8 04 00 00 00 BA 03 00 00 00 C7 44 24 54 01 00 }

	condition:
		all of them
}
