rule Linux_Trojan_Tsunami_55a80ab6
{
	meta:
		author = "Elastic Security"
		id = "55a80ab6-3de4-48e1-a9de-28dc3edaa104"
		fingerprint = "2fe3a9e1115d8c2269fe090c57ee3d5b2cd52b4ba1d020cec0135e2f8bbcb50e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 74 68 65 20 63 75 72 72 65 6E 74 20 73 70 6F 6F 66 69 6E 67 }

	condition:
		all of them
}
