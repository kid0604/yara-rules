rule MacOS_Cryptominer_Generic_365ecbb9
{
	meta:
		author = "Elastic Security"
		id = "365ecbb9-586e-4962-a5a8-05e871f54eff"
		fingerprint = "5ff82ab60f8d028c9e4d3dd95609f92cfec5f465c721d96947b490691d325484"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Cryptominer.Generic"
		reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 55 6E 6B 6E 6F 77 6E 20 6E 65 74 77 6F 72 6B 20 73 70 65 63 69 66 69 65 64 20 }

	condition:
		all of them
}
