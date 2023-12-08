rule Linux_Trojan_Mirai_64d5cde2
{
	meta:
		author = "Elastic Security"
		id = "64d5cde2-e4b1-425b-8af3-314a5bf519a9"
		fingerprint = "1a69f91b096816973ce0c2e775bcf2a54734fa8fbbe6ea1ffcf634ce2be41767"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "caf2a8c199156db2f39dbb0a303db56040f615c4410e074ef56be2662752ca9d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 64d5cde2"
		filetype = "executable"

	strings:
		$a = { 0F 35 7E B3 02 00 D0 02 00 00 07 01 00 00 0E 00 00 00 18 03 00 }

	condition:
		all of them
}
