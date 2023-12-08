rule Linux_Trojan_Mirai_4032ade1
{
	meta:
		author = "Elastic Security"
		id = "4032ade1-4864-4637-ae73-867cd5fb7378"
		fingerprint = "2b150a6571f5a2475d0b4a2ddb75623d6fa1c861f5385a5c42af24db77573480"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "6150fbbefb916583a0e888dee8ed3df8ec197ba7c04f89fb24f31de50226e688"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 4032ade1"
		filetype = "executable"

	strings:
		$a = { F8 0C 67 56 55 4C 06 87 DE B2 C0 79 AE 88 73 79 0C 7E F8 87 }

	condition:
		all of them
}
