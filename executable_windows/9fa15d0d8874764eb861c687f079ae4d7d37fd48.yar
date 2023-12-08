rule APT_MAL_WildNeutron_javacpl
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		modified = "2023-01-06"
		old_rule_name = "WildNeutron_javacpl"
		score = 60
		hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
		hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
		hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" ascii fullword
		$s2 = "cmdcmdline" wide fullword
		$s3 = "\"%s\" /K %s" wide fullword
		$s4 = "Process is not running any more" wide fullword
		$s5 = "dpnxfsatz" wide fullword
		$op1 = { ff d6 50 ff 15 ?? ?? 43 00 8b f8 85 ff 74 34 83 64 24 0c 00 e8 ?? ?? 02 00 }
		$op2 = { b8 02 00 00 00 01 45 80 01 45 88 6a 00 47 52 89 7d 8c 03 d8 }
		$op3 = { 8b c7 f7 f6 46 89 b5 c8 fd ff ff 0f b7 c0 8b c8 0f af ce 3b cf }

	condition:
		uint16(0)==0x5a4d and filesize <5MB and ( all of ($s*) or all of ($op*))
}
