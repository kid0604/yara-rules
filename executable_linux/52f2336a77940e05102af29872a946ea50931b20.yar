rule Linux_Cryptominer_Generic_b6ea5ee1
{
	meta:
		author = "Elastic Security"
		id = "b6ea5ee1-ede5-4fa3-a065-99219b3530da"
		fingerprint = "07c2f1fcb50ce5bcdebfc03fca4aaacdbabab42a857d7cc8f008712ca576b871"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 47 20 49 8D 77 20 4C 89 74 24 10 4C 89 6C 24 18 4C 89 64 24 20 }

	condition:
		all of them
}
