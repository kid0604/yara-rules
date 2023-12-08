rule Windows_Trojan_Trickbot_28a60148
{
	meta:
		author = "Elastic Security"
		id = "28a60148-2efb-4cd2-ada1-dd2ae2699adf"
		fingerprint = "c857aa792ef247bfcf81e75fb696498b1ba25c09fc04049223a6dfc09cc064b1"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant 28a60148"
		filetype = "executable"

	strings:
		$a = { C0 31 E8 83 7D 0C 00 89 44 24 38 0F 29 44 24 20 0F 29 44 24 10 0F 29 }

	condition:
		all of them
}
