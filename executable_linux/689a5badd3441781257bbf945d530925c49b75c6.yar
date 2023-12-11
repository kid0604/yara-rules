rule Linux_Exploit_CVE_2014_3153_1c1e02ad
{
	meta:
		author = "Elastic Security"
		id = "1c1e02ad-eb06-4eb6-a424-0f1dd6eebb2a"
		fingerprint = "a0a82cd15713be3f262021d6ed6572a0d4763ccfd0499e6b9374764c89705c2a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2014-3153"
		reference_sample = "64b8c61b73f0c0c0bd44ea5c2bcfb7b665fcca219dbe074a4a16ae20cd565812"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2014-3153"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 8D 4D D0 48 8B 45 C8 BA 24 00 }

	condition:
		all of them
}
