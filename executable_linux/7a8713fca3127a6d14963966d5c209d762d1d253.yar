rule Linux_Exploit_CVE_2016_5195_b2ebdebd
{
	meta:
		author = "Elastic Security"
		id = "b2ebdebd-0110-46b4-a97f-27c4c495b23d"
		fingerprint = "2a98a2d1be205145eb2d30a57aaa547b30281b31981f0872ba3f7e1d684a0cc2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "dee49d4b7f406fd1728dad4dc217484ced2586e014e2cd265ea64eff70a2633d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 30 48 89 7D D8 48 8B 45 D8 48 89 45 F8 BE 02 00 }

	condition:
		all of them
}
