rule Linux_Cryptominer_Camelot_209b02dd
{
	meta:
		author = "Elastic Security"
		id = "209b02dd-3087-475b-8d28-baa18647685b"
		fingerprint = "5829daea974d581bb49ac08150b63b7b24e6fae68f669b6b7ab48418560894d4"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "60d33d1fdabc6b10f7bb304f4937051a53d63f39613853836e6c4d095343092e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 45 31 F5 44 0B 5C 24 F4 41 C1 EA 10 44 0B 54 24 }

	condition:
		all of them
}
