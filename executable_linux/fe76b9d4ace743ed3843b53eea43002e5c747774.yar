rule Linux_Exploit_Vmsplice_cfa94001
{
	meta:
		author = "Elastic Security"
		id = "cfa94001-6000-4633-9af2-efabfaa96f94"
		fingerprint = "3fb484112484e2afc04a88d50326312af950605c61f258651479427b7bae300a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Vmsplice"
		reference_sample = "0a26e67692605253819c489cd4793a57e86089d50150124394c30a8801bf33e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Vmsplice"
		filetype = "executable"

	strings:
		$a = { 7A 00 21 40 23 24 00 6D 6D 61 70 00 5B 2B 5D 20 6D 6D 61 70 3A }

	condition:
		all of them
}
