rule Linux_Trojan_Iroffer_7478ddd9
{
	meta:
		author = "Elastic Security"
		id = "7478ddd9-ebb6-4bd4-a1ad-d0bf8f99ab1d"
		fingerprint = "b497ee116b77e2ba1fedfad90894d956806a2ffa19cadc33a916513199b0a381"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Iroffer"
		reference_sample = "20e1509c23d7ef14b15823e4c56b9a590e70c5b7960a04e94b662fc34152266c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Iroffer with fingerprint 7478ddd9"
		filetype = "executable"

	strings:
		$a = { 80 FA 0F 74 10 80 FA 16 74 0B 80 FA 1F 74 06 C6 04 1E 2E 89 }

	condition:
		all of them
}
