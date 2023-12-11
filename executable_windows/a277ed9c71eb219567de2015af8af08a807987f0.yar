rule Windows_Trojan_Trickbot_f2a18b09
{
	meta:
		author = "Elastic Security"
		id = "f2a18b09-f7b3-4d1a-87ab-3018f520b69c"
		fingerprint = "3e4474205efe22ea0185c49052e259bc08de8da7c924372f6eb984ae36b91a1c"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant with fingerprint f2a18b09"
		filetype = "executable"

	strings:
		$a = { 04 39 45 08 75 08 8B 4D F8 8B 41 18 EB 0F 8B 55 F8 8B 02 89 }

	condition:
		all of them
}
