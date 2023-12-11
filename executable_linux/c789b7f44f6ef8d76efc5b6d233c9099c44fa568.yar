rule Linux_Exploit_CVE_2016_5195_ccfd7518
{
	meta:
		author = "Elastic Security"
		id = "ccfd7518-af6c-4378-bd9c-7267a7f0dab4"
		fingerprint = "4797064d6416f2799691ae7df956d0383dfe6094de29fb03fc8233ad89149942"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "b1017db71cf195aa565c57fed91ff1cdfcce344dc76526256d5817018f1351bf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 83 45 FC 01 81 7D FC FF E0 F5 05 7F 0A 8B 05 }

	condition:
		all of them
}
