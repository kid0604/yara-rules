rule Linux_Cryptominer_Camelot_b8552fff
{
	meta:
		author = "Elastic Security"
		id = "b8552fff-29a9-4e09-810a-b4b52a7a3fb4"
		fingerprint = "d5998e0bf7df96dd21d404658589fb37b405398bd3585275419169b30c72ce62"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot malware"
		filetype = "executable"

	strings:
		$a = { 18 8B 44 24 1C 8B 50 0C 83 E8 04 8B 0A FF 74 24 28 FF 74 24 28 FF 74 }

	condition:
		all of them
}
