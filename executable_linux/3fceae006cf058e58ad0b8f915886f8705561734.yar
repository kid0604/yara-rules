rule Linux_Cryptominer_Loudminer_851fc7aa
{
	meta:
		author = "Elastic Security"
		id = "851fc7aa-6514-4f47-b6b5-a1e730b5d460"
		fingerprint = "e4d78229c1877a023802d7d99eca48bffc55d986af436c8a1df7c6c4e5e435ba"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Loudminer"
		reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Loudminer malware"
		filetype = "executable"

	strings:
		$a = { 49 8B 45 00 4C 8B 40 08 49 8D 78 18 49 89 FA 49 29 D2 49 01 C2 4C }

	condition:
		all of them
}
