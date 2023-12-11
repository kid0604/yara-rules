rule Windows_Trojan_CobaltStrike_3dc22d14
{
	meta:
		author = "Elastic Security"
		id = "3dc22d14-a2f4-49cd-a3a8-3f071eddf028"
		fingerprint = "0e029fac50ffe8ea3fc5bc22290af69e672895eaa8a1b9f3e9953094c133392c"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CobaltStrike"
		filetype = "executable"

	strings:
		$a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$a2 = "%s as %s\\%s: %d" fullword

	condition:
		all of them
}
