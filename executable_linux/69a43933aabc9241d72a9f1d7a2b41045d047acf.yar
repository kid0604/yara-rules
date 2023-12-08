rule Linux_Exploit_CVE_2016_5195_7448814c
{
	meta:
		author = "Elastic Security"
		id = "7448814c-1685-45a9-9a00-039b30485545"
		fingerprint = "25ffa8f3b2356deebc88d8831bc8664edd6543a7d722d6ddd72e89fad18c66e7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "e95d0783b635e34743109d090af17aef2e507e8c90060d171e71d9ac79e083ba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 9C 01 7E 24 48 8B 45 90 48 8B 40 08 48 89 45 C0 48 8B 45 C0 48 }

	condition:
		all of them
}
