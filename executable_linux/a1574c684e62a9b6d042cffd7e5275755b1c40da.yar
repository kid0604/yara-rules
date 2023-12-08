rule Linux_Exploit_CVE_2016_5195_3b460716
{
	meta:
		author = "Elastic Security"
		id = "3b460716-812e-4884-ab66-e01f2e61996d"
		fingerprint = "900e22d1a157677698a47d49d2deeb52c938e3a790aba689b920ba1bbd7ed39d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "8c4d49d4881ebdab1bd0e083d4e644cfc8eb7af3b96664598526ab3d175fc420"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 30 48 89 7D D8 48 8B 45 D8 48 89 45 E8 BE 02 00 }

	condition:
		all of them
}
