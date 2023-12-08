rule EquationGroup__jparsescan_parsescan_5
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files jparsescan, parsescan"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		super_rule = 1
		hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
		hash2 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "# default is to dump out all scanned hosts found" fullword ascii
		$s2 = "$bool .= \" -r \" if (/mibiisa.* -r/);" fullword ascii
		$s3 = "sadmind is available on two ports, this also works)" fullword ascii
		$s4 = "-x IP      gives \\\"hostname:# users:load ...\\\" if positive xwin scan" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <40KB and 1 of them ) or (2 of them )
}
