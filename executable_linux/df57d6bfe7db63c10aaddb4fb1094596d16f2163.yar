rule Linux_Trojan_Mirai_0cb1699c
{
	meta:
		author = "Elastic Security"
		id = "0cb1699c-9a08-4885-aa7f-0f1ee2543cac"
		fingerprint = "6e44c68bba8c9fb53ac85080b9ad765579f027cabfea5055a0bb3a85b8671089"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 0cb1699c"
		filetype = "executable"

	strings:
		$a = { DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 10 0F B7 02 83 E9 02 83 }

	condition:
		all of them
}
