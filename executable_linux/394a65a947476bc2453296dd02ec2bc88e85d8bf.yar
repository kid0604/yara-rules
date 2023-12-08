rule Linux_Cryptominer_Uwamson_0797de34
{
	meta:
		author = "Elastic Security"
		id = "0797de34-9181-4f28-a4b0-eafa67e20b41"
		fingerprint = "b6a210c23f09ffa0114f12aa741be50f234b8798a3275ac300aa17da29b8727c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Uwamson"
		reference_sample = "e4699e35ce8091f97decbeebff63d7fa8c868172a79f9d9d52b6778c3faab8f2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Uwamson malware"
		filetype = "executable"

	strings:
		$a = { 43 20 48 B9 AB AA AA AA AA AA AA AA 88 44 24 30 8B 43 24 89 44 }

	condition:
		all of them
}
