rule Linux_Cryptominer_Loudminer_f2298a50
{
	meta:
		author = "Elastic Security"
		id = "f2298a50-7bd4-43d8-ac84-b36489405f2e"
		fingerprint = "8eafc1c995c0efb81d9ce6bcc107b102551371f3fb8efdf8261ce32631947e03"
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
		$a = { B6 04 07 41 8D 40 D0 3C 09 76 AD 41 8D 40 9F 3C 05 76 A1 41 8D }

	condition:
		all of them
}
