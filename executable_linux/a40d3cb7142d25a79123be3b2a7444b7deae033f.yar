rule Linux_Exploit_CVE_2016_5195_9190d516
{
	meta:
		author = "Elastic Security"
		id = "9190d516-dea0-4d74-9f2c-bd2337538258"
		fingerprint = "977bafd175a994edaef5f3fa19d19fe161cebb2447ee32fd5d4b0a3b93fb51fa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "837ffed1f23293dc9c7cb994601488fc121751a249ffde51326947c33c5fca7f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 4D 18 48 8B 55 10 48 8B 75 F0 48 8B 45 F8 48 83 EC 08 41 51 }

	condition:
		all of them
}
