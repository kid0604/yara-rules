rule Linux_Cryptominer_Generic_69e1a763
{
	meta:
		author = "Elastic Security"
		id = "69e1a763-1e0d-4448-9bc4-769f3a36ac10"
		fingerprint = "9007ab73902ef9bfa69e4ddc29513316cb6aa7185986cdb10fd833157cd7d434"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "b04d9fabd1e8fc42d1fa8e90a3299a3c36e6f05d858dfbed9f5e90a84b68bcbb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 43 08 49 89 46 08 48 8B 43 10 49 89 46 10 48 85 C0 74 8A F0 83 40 }

	condition:
		all of them
}
