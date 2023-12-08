rule EquationGroup_parsescan
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
		$s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
