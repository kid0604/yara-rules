rule Linux_Exploit_CVE_2009_2908_406c2fef
{
	meta:
		author = "Elastic Security"
		id = "406c2fef-0f1a-441a-96b9-e4168c283c90"
		fingerprint = "94a94217823a8d682ba27889ba2b53fef7b18ae14d75a73456f21184e51581cf"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2009-2908"
		reference_sample = "1e05a23f5b3b9cfde183aec26b723147e1816b95dc0fb7f9ac57376efcb22fcd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit for CVE-2009-2908"
		filetype = "executable"

	strings:
		$a = { 74 00 66 70 72 69 6E 74 66 00 66 77 72 69 74 65 00 64 65 73 }

	condition:
		all of them
}
