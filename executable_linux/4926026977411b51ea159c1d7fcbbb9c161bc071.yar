rule Linux_Trojan_Generic_703a0258
{
	meta:
		author = "Elastic Security"
		id = "703a0258-8d28-483e-a679-21d9ef1917b4"
		fingerprint = "796c2283eb14057081409800480b74ab684413f8f63a9db8704f5057026fb556"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "b086d0119042fc960fe540c23d0a274dd0fb6f3570607823895c9158d4f75974"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with fingerprint 703a0258"
		filetype = "executable"

	strings:
		$a = { C2 F7 89 76 7E 86 87 F6 2B A3 2C 94 61 36 BE B6 }

	condition:
		all of them
}
