rule Linux_Exploit_Lotoor_fbff22da
{
	meta:
		author = "Elastic Security"
		id = "fbff22da-2f31-416c-8aa0-1003e3be8baa"
		fingerprint = "b649b172fad3e3b085cbf250bd17dbea4c409a7337914c63230d188f9b8135fa"
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
		$a = { 00 75 6E 61 6D 65 00 73 74 72 6C 65 6E 00 73 74 64 6F 75 74 00 }

	condition:
		all of them
}
