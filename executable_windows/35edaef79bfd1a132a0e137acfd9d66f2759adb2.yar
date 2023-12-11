rule Windows_Trojan_Trickbot_cd0868d5
{
	meta:
		author = "Elastic Security"
		id = "cd0868d5-42d8-437f-8c1a-303526c08442"
		fingerprint = "2f777285a90fce20cd4eab203f3ec7ed1c62e09fc2dfdce09b57e0802f49628f"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot"
		filetype = "executable"

	strings:
		$a = { 8D 1C 01 89 54 24 10 8B 54 24 1C 33 C9 66 8B 0B 8D 3C 8A 8B 4C }

	condition:
		all of them
}
