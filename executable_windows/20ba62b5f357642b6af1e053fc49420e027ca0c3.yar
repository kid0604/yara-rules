rule Windows_Trojan_Trickbot_52722678
{
	meta:
		author = "Elastic Security"
		id = "52722678-afbe-43ec-a39b-6848b7d49488"
		fingerprint = "e67dda5227be74424656957843777ea533b6800576fd85f978fd8fb50504209c"
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
		$a = { 2B 5D 0C 89 5D EC EB 03 8B 5D EC 8A 1C 3B 84 DB 74 0D 38 1F }

	condition:
		all of them
}
