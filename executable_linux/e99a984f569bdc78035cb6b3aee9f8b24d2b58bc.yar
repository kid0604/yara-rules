rule Linux_Cryptominer_Generic_b9e6ffdf
{
	meta:
		author = "Elastic Security"
		id = "b9e6ffdf-4b2b-4052-9c91-a06f43a2e7b8"
		fingerprint = "fdd91d5802d5807d52f4c9635e325fc0765bb54cf51305c7477d2b791f393f3e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "c0f3200a93f1be4589eec562c4f688e379e687d09c03d1d8850cc4b5f90f192a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 89 D8 48 83 C4 20 5B C3 0F 1F 00 BF ?? ?? 40 00 }

	condition:
		all of them
}
