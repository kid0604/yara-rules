rule Linux_Cryptominer_Generic_e73f501e
{
	meta:
		author = "Elastic Security"
		id = "e73f501e-019c-4281-ae93-acde7ad421af"
		fingerprint = "bd9e6f2548c918b2c439a047410b6b239c3993a3dbd85bfd70980c64d11a6c5c"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "2f646ced4d05ba1807f8e08a46ae92ae3eea7199e4a58daf27f9bd0f63108266"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 03 51 8A 92 FF F3 20 01 DE 63 AF 8B 54 73 0A 65 83 64 88 60 }

	condition:
		all of them
}
