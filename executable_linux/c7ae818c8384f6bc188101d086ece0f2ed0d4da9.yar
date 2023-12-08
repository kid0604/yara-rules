rule Linux_Trojan_Mirai_ab073861
{
	meta:
		author = "Elastic Security"
		id = "ab073861-38df-4a39-ab81-8451b6fab30c"
		fingerprint = "37ab5e3ccc9a91c885bff2b1b612efbde06999e83ff5c5cd330bd3a709a831f5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "175444a9c9ca78565de4b2eabe341f51b55e59dec00090574ee0f1875422cbac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { AC 00 00 00 54 60 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }

	condition:
		all of them
}
