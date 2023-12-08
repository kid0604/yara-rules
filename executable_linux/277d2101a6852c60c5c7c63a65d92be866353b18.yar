rule Linux_Cryptominer_Malxmr_fe7139e5
{
	meta:
		author = "Elastic Security"
		id = "fe7139e5-3c8e-422c-aaf7-e683369d23d4"
		fingerprint = "4af38ca3ec66ca86190e6196a9a4ba81a0a2b77f88695957137f6cda8fafdec9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "8b13dc59db58b6c4cd51abf9c1d6f350fa2cb0dbb44b387d3e171eacc82a04de"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { FF 74 5B 48 29 F9 49 89 DC 4C 8D 69 01 49 D1 ED 4C 01 E9 4D 8D 6C }

	condition:
		all of them
}
