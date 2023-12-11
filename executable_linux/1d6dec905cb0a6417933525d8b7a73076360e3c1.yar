rule Linux_Exploit_Abrox_5641ba81
{
	meta:
		author = "Elastic Security"
		id = "5641ba81-2c37-4dd1-82d8-532182e8ed15"
		fingerprint = "d2abedb6182f86982ebe283215331ce238fda3964535047768f2ea55719b052f"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Abrox"
		reference_sample = "8de96c8e61536cae870f4a24127d28b86bd8122428bf13965c596f92182625aa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Abrox malware"
		filetype = "executable"

	strings:
		$a = { 04 58 CD 80 6A 17 58 31 DB CD 80 31 D2 52 68 2E }

	condition:
		all of them
}
