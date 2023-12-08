rule Linux_Exploit_Enoket_7da5f86a
{
	meta:
		author = "Elastic Security"
		id = "7da5f86a-c177-47c9-a82e-50648c84174a"
		fingerprint = "cf9a703969e3f9a3cd20119fc0a24fa2d16bec5ea7e3b1a8df763872625c90fc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Enoket"
		reference_sample = "406b003978d79d453d3e2c21b991b113bf2fc53ffbf3a1724c5b97a4903ef550"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Enoket"
		filetype = "executable"

	strings:
		$a = { FF 75 F2 80 7D 94 00 74 23 0F B6 0F B8 01 00 00 00 3A 4D 94 }

	condition:
		all of them
}
