rule EquationGroup__funnelout_v4_1_0_1
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files funnelout.v4.1.0.1.pl"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		super_rule = 1
		hash2 = "457ed14e806fdbda91c4237c8dc058c55e5678f1eecdd78572eff6ca0ed86d33"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "header(\"Set-Cookie: bbsessionhash=\" . \\$hash . \"; path=/; HttpOnly\");" fullword ascii
		$s2 = "if ($code =~ /proxyhost/) {" fullword ascii
		$s3 = "\\$rk[1] = \\$rk[1] - 1;" fullword ascii
		$s4 = "#existsUser($u) or die \"User '$u' does not exist in database.\\n\";" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <100KB and 2 of them ) or ( all of them )
}
