rule Linux_Cryptominer_Generic_d81368a3
{
	meta:
		author = "Elastic Security"
		id = "d81368a3-00ca-44cf-b009-718272d389eb"
		fingerprint = "dd463df2c03389af3e7723fda684b0f42342817b3a76664d131cf03542837b8a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "71225e4702f2e0a0ecf79f7ec6c6a1efc95caf665fda93a646519f6f5744990b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { CB 49 C1 E3 04 49 01 FB 41 8B 13 39 D1 7F 3F 7C 06 4D 3B 43 08 }

	condition:
		all of them
}
