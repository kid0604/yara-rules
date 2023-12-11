rule Linux_Exploit_Lotoor_7cd57e18
{
	meta:
		author = "Elastic Security"
		id = "7cd57e18-2315-419b-b373-ea801181232c"
		fingerprint = "a7d3183de1bccd816bcd2346e9754aaf6e7eb124d7416d79bdbe422b33035414"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "1eecf16dae302ae788d1bc81278139cd9f6af52d7bed48b8677b35ba5eb14e30"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 76 65 3A 20 4C 69 6E 75 78 20 32 2E 36 2E }

	condition:
		all of them
}
