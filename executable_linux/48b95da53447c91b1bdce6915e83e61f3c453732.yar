rule Linux_Cryptominer_Loudminer_581f57a9
{
	meta:
		author = "Elastic Security"
		id = "581f57a9-36e0-4b95-9a1e-837bdd4aceab"
		fingerprint = "1013e6e11ea2a30ecf9226ea2618a59fb08588cdc893053430e969fbdf6eb675"
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
		$a = { 44 24 08 48 8B 70 20 48 8B 3B 48 83 C3 08 48 89 EA 48 8B 07 FF }

	condition:
		all of them
}
