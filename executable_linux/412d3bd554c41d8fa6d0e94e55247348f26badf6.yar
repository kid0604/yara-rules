rule Linux_Trojan_Mirai_402adc45
{
	meta:
		author = "Elastic Security"
		id = "402adc45-6279-44a6-b766-24706b0328fe"
		fingerprint = "01b88411c40abc65c24d7a335027888c0cf48ad190dd3fa1b8e17d086a9b80a0"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 402adc45"
		filetype = "executable"

	strings:
		$a = { C3 EB DF 5A 5B 5D 41 5C 41 5D C3 41 57 41 56 41 55 41 54 55 53 48 }

	condition:
		all of them
}
