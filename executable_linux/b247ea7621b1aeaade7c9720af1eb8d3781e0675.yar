rule Linux_Cryptominer_Malxmr_da08e491
{
	meta:
		author = "Elastic Security"
		id = "da08e491-c6fa-4228-8b6a-8adae2f0324a"
		fingerprint = "c4911fdeece4c3f97bbc9ef4da478c5f5363ab71a70b0767edec0f94b87fd939"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "4638d9ece32cd1385121146378772d487666548066aecd7e40c3ba5231f54cc0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { F9 48 31 CD 48 89 F9 48 F7 D1 4C 21 F9 48 21 DA 49 31 CA 48 }

	condition:
		all of them
}
