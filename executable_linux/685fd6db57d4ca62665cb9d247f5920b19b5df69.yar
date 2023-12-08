rule Linux_Cryptominer_Generic_28a80546
{
	meta:
		author = "Elastic Security"
		id = "28a80546-ae74-4616-8896-50f54da66650"
		fingerprint = "7f49f04ba36e7ff38d313930c469d64337203a60792f935a3548cee176ae9523"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "96cc225cf20240592e1dcc8a13a69f2f97637ed8bc89e30a78b8b2423991d850"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 72 59 D4 B5 63 E2 4D B6 08 EF E8 0A 3A B1 AD 1B 61 6E 7C 65 D1 }

	condition:
		all of them
}
