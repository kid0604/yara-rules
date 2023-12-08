rule Linux_Trojan_Ipstorm_f9269f00
{
	meta:
		author = "Elastic Security"
		id = "f9269f00-4664-47a4-9148-fa74e2cfee7c"
		fingerprint = "509de41454bcc60dad0d96448592aa20fb997ce46ad8fed5d4bbdbe2ede588d6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ipstorm"
		reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ipstorm"
		filetype = "executable"

	strings:
		$a = { EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 B8 69 00 }

	condition:
		all of them
}
