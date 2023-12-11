rule Linux_Exploit_Sorso_ecf99f8f
{
	meta:
		author = "Elastic Security"
		id = "ecf99f8f-1692-41ee-a70d-8c868e269529"
		fingerprint = "d2c0ccceed8a76d13c8b388e5c3b560f23ecff2b1b9c90d18e5e0d0bbdc91364"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Sorso"
		reference_sample = "c0f0a7b45fb91bc18264d901c20539dd32bc03fa5b7d839a0ef5012fb0d895cd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Sorso"
		filetype = "executable"

	strings:
		$a = { 6E 89 E3 50 54 53 50 B0 3B CD 80 31 C0 B0 01 CD }

	condition:
		all of them
}
