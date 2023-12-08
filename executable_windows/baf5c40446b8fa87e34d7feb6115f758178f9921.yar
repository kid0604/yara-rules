rule Windows_Trojan_Trickbot_be718af9
{
	meta:
		author = "Elastic Security"
		id = "be718af9-5995-4ae2-ba55-504e88693c96"
		fingerprint = "047b1c64b8be17d4a6030ab2944ad715380f53a8a6dd9c8887f198693825a81d"
		creation_date = "2021-03-30"
		last_modified = "2021-08-23"
		description = "Targets permadll module used to fingerprint BIOS/firmaware data"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "c1f1bc58456cff7413d7234e348d47a8acfdc9d019ae7a4aba1afc1b3ed55ffa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "user_platform_check.dll" ascii fullword
		$a2 = "<moduleconfig><nohead>yes</nohead></moduleconfig>" ascii fullword
		$a3 = "DDEADFDEEEEE"
		$a4 = "\\`Ruuuuu_Exs|_" ascii fullword
		$a5 = "\"%pueuu%" ascii fullword

	condition:
		3 of ($a*)
}
