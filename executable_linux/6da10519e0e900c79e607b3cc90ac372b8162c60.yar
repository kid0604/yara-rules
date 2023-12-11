rule Linux_Cryptominer_Malxmr_70e5946e
{
	meta:
		author = "Elastic Security"
		id = "70e5946e-3e73-4b07-9e7d-af036a3242f9"
		fingerprint = "ced6885fda17c862753232fde3e7e8797f5a900ebab7570b78aa7138a0068eb9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 4F 70 48 8D B4 24 B0 00 00 00 48 89 34 CA 49 8B 57 68 48 89 C8 83 }

	condition:
		all of them
}
