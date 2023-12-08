rule Linux_Cryptominer_Malxmr_c8adb449
{
	meta:
		author = "Elastic Security"
		id = "c8adb449-3de5-4cdd-9b62-fe4bcbe82394"
		fingerprint = "838950826835e811eb7ea3af7a612b4263d171ded4761d2b547a4012adba4028"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "00ec7a6e9611b5c0e26c148ae5ebfedc57cf52b21e93c2fe3eac85bf88edc7ea"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { D2 4C 89 54 24 A0 4C 89 FA 48 F7 D2 48 23 54 24 88 49 89 D2 48 8B 54 }

	condition:
		all of them
}
