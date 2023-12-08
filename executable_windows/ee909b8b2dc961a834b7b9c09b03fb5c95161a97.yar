rule Windows_Trojan_Trickbot_ce4305d1
{
	meta:
		author = "Elastic Security"
		id = "ce4305d1-8a6f-4797-afaf-57e88f3d38e6"
		fingerprint = "ae606e758b02ccf2a9a313aebb10773961121f79a94c447e745289ee045cf4ee"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot (ce4305d1) based on specific fingerprint"
		filetype = "executable"

	strings:
		$a = { F9 8B 45 F4 89 5D E4 85 D2 74 39 83 C0 02 03 C6 89 45 F4 8B }

	condition:
		all of them
}
