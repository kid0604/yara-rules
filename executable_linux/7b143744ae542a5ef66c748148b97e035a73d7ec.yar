rule Linux_Exploit_Lotoor_757637d9
{
	meta:
		author = "Elastic Security"
		id = "757637d9-6171-4e2a-bf7c-3ee2c71066a7"
		fingerprint = "7fa3e2432ddd696b5d40aafbde1e026e74294d31c9201800ce66b343a3724c6e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "0762fa4e0d74e3c21b2afc8e4c28e2292d1c3de3683c46b5b77f0f9fe1faeec7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 64 00 73 70 72 69 6E 74 66 00 6F 70 65 6E 00 69 73 5F 6F 6C }

	condition:
		all of them
}
