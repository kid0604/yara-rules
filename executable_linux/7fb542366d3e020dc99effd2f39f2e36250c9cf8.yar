rule Linux_Exploit_CVE_2016_5195_3a2ed31b
{
	meta:
		author = "Elastic Security"
		id = "3a2ed31b-a8be-4aff-af5e-e1ff2676f3f9"
		fingerprint = "0e8e0f58deadf4838464c2f2bc860013e6d47c3d770d0ef743b5dd9021832cae"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "ebbf3bc39ec661e2029d88960a5608e348de92089099019348bc0e891841690f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 30 48 89 7D D8 48 8B 45 D8 48 89 45 F0 BE 02 00 }

	condition:
		all of them
}
