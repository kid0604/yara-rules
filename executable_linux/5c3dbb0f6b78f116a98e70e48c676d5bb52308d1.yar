rule Linux_Exploit_CVE_2009_2698_12374e97
{
	meta:
		author = "Elastic Security"
		id = "12374e97-385e-4b3a-9d50-39f35ad4f6dd"
		fingerprint = "2c669220ac8909e2336bbf9c38489c8e32d573ab6c29fa1e2e0c1fe69f7441ed"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2009-2698"
		reference_sample = "656fddc1bf4743a08a455628b6151076b81e604ff49c93d797fa49b1f7d09c2f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2009-2698"
		filetype = "executable"

	strings:
		$a = { 74 64 6F 75 74 00 66 77 72 69 74 65 00 64 65 73 63 00 63 76 65 00 }

	condition:
		all of them
}
