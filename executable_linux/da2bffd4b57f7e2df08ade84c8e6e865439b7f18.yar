rule Linux_Cryptominer_Malxmr_ce0c185f
{
	meta:
		author = "Elastic Security"
		id = "ce0c185f-fca2-47d3-9e7c-57b541af98a5"
		fingerprint = "0d2e3e2b04e93f25c500677482e15d92408cb1da2a5e3c5a13dc71e52d140f85"
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
		$a = { EF E5 66 0F 6F AC 24 80 00 00 00 66 0F EB E8 66 0F EF D5 66 0F }

	condition:
		all of them
}
