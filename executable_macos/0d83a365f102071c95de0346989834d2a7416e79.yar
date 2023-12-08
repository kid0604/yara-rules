rule MacOS_Cryptominer_Generic_333129b7
{
	meta:
		author = "Elastic Security"
		id = "333129b7-8137-4641-bd86-ebcf62257d7b"
		fingerprint = "baa9e777683d31c27170239752f162799a511bf40269a06a2eab8971fabb098a"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Cryptominer.Generic"
		reference_sample = "bf47d27351d6b0be0ffe1d6844e87fe8f4f4d33ea17b85c11907266d36e4b827"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 6D BF 81 55 D4 4C D4 19 4C 81 18 24 3C 14 3C 30 14 18 26 79 5F 35 5F 4C 35 26 }

	condition:
		all of them
}
