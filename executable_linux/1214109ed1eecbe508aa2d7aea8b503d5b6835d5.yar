rule Linux_Trojan_Tsunami_f806d5d9
{
	meta:
		author = "Elastic Security"
		id = "f806d5d9-0bf6-4da7-80fb-b1612f2ddd5b"
		fingerprint = "f4f838fcd1fe7f85e435225f3e34b77b848246b2b9618b47125a611c8d282347"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Tsunami malware"
		filetype = "executable"

	strings:
		$a = { 41 54 45 48 54 54 50 20 3C 68 6F 73 74 3E 20 3C 73 72 63 3A }

	condition:
		all of them
}
