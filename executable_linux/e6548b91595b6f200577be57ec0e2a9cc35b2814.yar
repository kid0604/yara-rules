rule Linux_Cryptominer_Generic_616afaa1
{
	meta:
		author = "Elastic Security"
		id = "616afaa1-7679-4198-9e80-c3f044b3c07d"
		fingerprint = "fd6afad9f318ce00b0f0f8be3a431a2c7b4395dd69f82328f4555b3715a8b298"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "0901672d2688660baa26fdaac05082c9e199c06337871d2ae40f369f5d575f71"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 4B 04 31 C0 41 8B 14 07 89 14 01 48 83 C0 04 48 83 F8 14 75 EF 4C 8D 74 }

	condition:
		all of them
}
