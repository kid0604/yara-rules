rule Linux_Cryptominer_Generic_76cb94a9
{
	meta:
		author = "Elastic Security"
		id = "76cb94a9-5a3f-483c-91f3-aa0e3c27f7ba"
		fingerprint = "623a33cc95af46b8f0d557c69f8bf72db7c57fe2018b7a911733be4ddd71f073"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 8C 24 98 00 00 00 31 C9 80 7A 4A 00 48 89 74 24 18 48 89 54 }

	condition:
		all of them
}
