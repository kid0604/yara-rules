rule Windows_Exploit_Eternalblue_ead33bf8
{
	meta:
		author = "Elastic Security"
		id = "ead33bf8-1870-4d01-a223-edcbe262542f"
		fingerprint = "9e3b5f4f0b8ac683544886abbd9eecbf0253a7992ee5d99c453de67b9aacdccd"
		creation_date = "2021-01-12"
		last_modified = "2021-08-23"
		threat_name = "Windows.Exploit.Eternalblue"
		reference_sample = "a1340e418c80be58fb6bbb48d4e363de8c6d62ea59730817d5eda6ba17b2c7a7"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Eternalblue exploit"
		filetype = "executable"

	strings:
		$a = { F8 31 C9 EB 0B 40 8A 3C 0E 40 88 3C 08 48 FF C1 48 39 D1 75 }

	condition:
		all of them
}
