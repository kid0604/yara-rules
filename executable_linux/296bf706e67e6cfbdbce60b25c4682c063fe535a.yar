rule Linux_Trojan_Mirai_3e72e107
{
	meta:
		author = "Elastic Security"
		id = "3e72e107-3647-4afd-a556-3c49dae7eb0c"
		fingerprint = "3bca41fd44e5e9d8cdfb806fbfcaab3cc18baa268985b95e2f6d06ecdb58741a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "57d04035b68950246dd152054e949008dafb810f3705710d09911876cd44aec7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 3e72e107"
		filetype = "executable"

	strings:
		$a = { 10 85 C0 BA FF FF FF FF 74 14 8D 65 F4 5B 5E 5F 89 D0 5D C3 8D }

	condition:
		all of them
}
