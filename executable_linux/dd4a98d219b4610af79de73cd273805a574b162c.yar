rule Linux_Exploit_Local_2535c9b6
{
	meta:
		author = "Elastic Security"
		id = "2535c9b6-a575-4190-8e33-88758675e5b4"
		fingerprint = "4ec419bfd0ac83da2f826ba4cbd6a4b05bbd7b6f6cc077529ec4667b7d2f761a"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "d0f9cc114f6a1f788f36e359e03a9bbf89c075f41aec006229b6ad20ebbfba0b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { E8 63 F9 FF FF 83 7D D8 FF 75 14 BF 47 12 40 00 }

	condition:
		all of them
}
