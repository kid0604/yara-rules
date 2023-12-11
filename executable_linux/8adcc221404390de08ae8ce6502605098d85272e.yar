rule Linux_Exploit_CVE_2017_16995_5edb0181
{
	meta:
		author = "Elastic Security"
		id = "5edb0181-dfb1-47e2-873b-0fa3043bee67"
		fingerprint = "804635a4922830b894ed38f58751f481d389e5bfbea7a50912763952971844e6"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Exploit.CVE-2017-16995"
		reference_sample = "e4df84e1dffbad217d07222314a7e13fd74771a9111d07adc467a89d8ba81127"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2017-16995"
		filetype = "executable"

	strings:
		$a = { F8 2F 77 0F 45 89 C2 49 89 D1 41 83 C0 08 4A 8D 54 15 D0 48 }

	condition:
		all of them
}
