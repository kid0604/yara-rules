rule Linux_Cryptominer_Generic_5e56d076
{
	meta:
		author = "Elastic Security"
		id = "5e56d076-0d6d-4979-8ebc-52607dcdb42d"
		fingerprint = "e9ca9b9faee091afed534b89313d644a52476b4757663e1cdfbcbca379857740"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "32e1cb0369803f817a0c61f25ca410774b4f37882cab966133b4f3e9c74fac09"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 71 18 4C 89 FF FF D0 48 8B 84 24 A0 00 00 00 48 89 43 60 48 8B 84 24 98 00 }

	condition:
		all of them
}
