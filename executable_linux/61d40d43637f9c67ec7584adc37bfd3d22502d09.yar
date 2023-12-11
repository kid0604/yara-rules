rule Linux_Exploit_CVE_2016_5195_f1c0482a
{
	meta:
		author = "Elastic Security"
		id = "f1c0482a-fe88-4777-8d49-aa782bf25a98"
		fingerprint = "96d1ed843aeb59dd43dd76f4edd9e9928dd29f86df87b70d875473b9d908e75c"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "a12a1e8253ee1244b018fd3bdcb6b7729dfe16e06aed470f6b08344a110a4061"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { FF FF 88 45 F7 80 7D F7 FF 75 D6 B8 ?? ?? 04 08 }

	condition:
		all of them
}
