rule Linux_Cryptominer_Generic_397a86bd
{
	meta:
		author = "Elastic Security"
		id = "397a86bd-6d66-4db0-ad41-d0ae3dbbeb21"
		fingerprint = "0bad343f28180822bcb45b0a84d69b40e26e5eedb650db1599514020b6736dd0"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "79c47a80ecc6e0f5f87749319f6d5d6a3f0fbff7c34082d747155b9b20510cde"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 74 4F 48 8B 75 00 48 8B 4D 08 4C 89 F7 48 8B 55 10 48 8B 45 18 48 89 74 }

	condition:
		all of them
}
