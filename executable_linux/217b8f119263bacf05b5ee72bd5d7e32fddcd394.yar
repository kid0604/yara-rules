rule Linux_Cryptominer_Generic_fdd7340f
{
	meta:
		author = "Elastic Security"
		id = "fdd7340f-49d6-4770-afac-24104a3c2f86"
		fingerprint = "cc302eb6c133901cc3aa78e6ca0af16a620eb4dabb16b21d9322c4533f11d25f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { EA 48 89 DE 48 8D 7C 24 08 FF 53 18 48 8B 44 24 08 48 83 78 }

	condition:
		all of them
}
