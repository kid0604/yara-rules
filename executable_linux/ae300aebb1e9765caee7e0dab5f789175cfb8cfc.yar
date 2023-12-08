rule Linux_Cryptominer_Malxmr_a47b77e4
{
	meta:
		author = "Elastic Security"
		id = "a47b77e4-0d8d-4714-8527-7b783f0f27b8"
		fingerprint = "635a35defde186972cd6626bd75a1e557a1a9008ab93b38ef1a3635b3210354b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "995b43ccb20343494e314824343a567fd85f430e241fdeb43704d9d4937d76cc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 8D 48 49 5E 97 87 DC 73 86 19 51 B3 36 1A 6E FC 8C CC 2C 6E 0B }

	condition:
		all of them
}
