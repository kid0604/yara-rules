rule Linux_Cryptominer_Xmrminer_d625fcd2
{
	meta:
		author = "Elastic Security"
		id = "d625fcd2-2951-4ecf-91cd-d58e16c33c65"
		fingerprint = "08c8d00e38fbf62cbf0aa329d6293fba302c3c76aee8c33341260329c14a58aa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { 20 00 00 40 00 0C C0 5C 02 60 01 02 03 12 00 40 04 50 09 00 }

	condition:
		all of them
}
