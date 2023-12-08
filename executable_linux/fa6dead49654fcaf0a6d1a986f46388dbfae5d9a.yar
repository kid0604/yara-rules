rule Linux_Cryptominer_Generic_a5267ea3
{
	meta:
		author = "Elastic Security"
		id = "a5267ea3-b98c-49e9-8051-e33a101f12d3"
		fingerprint = "8391a4dbc361eec2877852acdc77681b3a15922d9a047d7ad12d06271d53f540"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "b342ceeef58b3eeb7a312038622bcce4d76fc112b9925379566b24f45390be7d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { EE 6A 00 41 B9 01 00 00 00 48 8D 4A 13 4C 89 E7 88 85 40 FF }

	condition:
		all of them
}
