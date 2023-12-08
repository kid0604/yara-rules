rule Linux_Cryptominer_Generic_4e9075e6
{
	meta:
		author = "Elastic Security"
		id = "4e9075e6-3ca9-459e-9f5f-3e614fd4f1c8"
		fingerprint = "70d8c4ecb185b8817558ad9d26a47c340c977abb6abfca8efe1ff99efb43c579"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "098bf2f1ce9d7f125e1c9618f349ae798a987316e95345c037a744964277f0fe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 2C 24 74 67 48 89 5C 24 18 4C 89 6C 24 20 4C 89 FB 4D 89 E5 4C 8B }

	condition:
		all of them
}
