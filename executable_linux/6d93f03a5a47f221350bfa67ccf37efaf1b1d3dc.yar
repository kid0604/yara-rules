rule Linux_Cryptominer_Generic_d7bd0e5d
{
	meta:
		author = "Elastic Security"
		id = "d7bd0e5d-3528-4648-aaa5-6cf44d22c0d5"
		fingerprint = "fbc06c7603aa436df807ad3f77d5ba783c4d33f61b06a69e8641741068f3a543"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "afcfd67af99e437f553029ccf97b91ed0ca891f9bcc01c148c2b38c75482d671"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { CF 99 67 D8 37 AA 24 80 F2 F3 47 6A A5 5E 88 50 F1 28 61 18 }

	condition:
		all of them
}
