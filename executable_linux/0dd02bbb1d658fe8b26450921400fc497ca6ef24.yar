rule Linux_Cryptominer_Generic_6a4f4255
{
	meta:
		author = "Elastic Security"
		id = "6a4f4255-d202-48b7-96ae-cb7211dcbea3"
		fingerprint = "0ed37d7eccd4e36b954824614b976e1371c3b2ffe318345d247198d387a13de6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { FD 48 8D 5D 01 4C 8D 14 1B 48 C1 E3 05 4C 01 EB 4D 8D 7A FF F2 0F }

	condition:
		all of them
}
