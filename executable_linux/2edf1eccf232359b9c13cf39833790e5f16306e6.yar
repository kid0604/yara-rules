rule Linux_Cryptominer_Malxmr_ad09e090
{
	meta:
		author = "Elastic Security"
		id = "ad09e090-098e-461d-b967-e45654b902bb"
		fingerprint = "a62729bbe04eca01dbb3c56de63466ed115f30926fc5d203c9bae75a93227e09"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 24 50 8B 44 24 64 89 54 24 54 39 C3 77 0E 72 08 8B 44 24 60 }

	condition:
		all of them
}
