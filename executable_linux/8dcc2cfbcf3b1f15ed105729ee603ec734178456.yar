rule Linux_Trojan_Mirai_e3e6d768
{
	meta:
		author = "Elastic Security"
		id = "e3e6d768-6510-4eb2-a5ec-8cb8eead13f2"
		fingerprint = "ce11f9c038c31440bcdf7f9d194d1a82be5d283b875cc6170a140c398747ff8c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "b505cb26d3ead5a0ef82d2c87a9b352cc0268ef0571f5e28defca7131065545e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with fingerprint e3e6d768"
		filetype = "executable"

	strings:
		$a = { 7E 14 48 89 DF 48 63 C8 4C 89 E6 FC F3 A4 41 01 C5 48 89 FB }

	condition:
		all of them
}
