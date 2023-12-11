rule Linux_Cryptominer_Generic_1512cf40
{
	meta:
		author = "Elastic Security"
		id = "1512cf40-ae62-40cf-935d-589be4fe3d93"
		fingerprint = "f9800996d2e6d9ea8641d51aedc554aa732ebff871f0f607bb3fe664914efd5a"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "fc063a0e763894e86cdfcd2b1c73d588ae6ecb411c97df2a7a802cd85ee3f46d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { C4 10 5B C3 E8 35 A7 F6 FF 0F 1F 44 00 00 53 48 }

	condition:
		all of them
}
