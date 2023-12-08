rule Linux_Exploit_Lotoor_78543893
{
	meta:
		author = "Elastic Security"
		id = "78543893-7180-4857-8951-4190ca4602f1"
		fingerprint = "b581e0820d7895021841d67e4e9dc40cec8f5ae5ba4dbc0585abcb76f97c9a2f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "ff5b02d2b4dfa9c3d53e7218533f3c57e82315be8f62aa17e26eda55a3b53479"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 00 48 8B 48 08 48 8B 54 24 F0 48 63 C6 48 89 8C C2 88 00 00 00 83 44 24 }

	condition:
		all of them
}
