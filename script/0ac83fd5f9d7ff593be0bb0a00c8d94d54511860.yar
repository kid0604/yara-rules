rule EquationGroup_ys_alt_1
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ys.auto"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "a6387307d64778f8d9cfc60382fdcf0627cde886e952b8d73cc61755ed9fde15"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "EXPLOIT_SCRIPME=\"$EXPLOIT_SCRIPME\"" fullword ascii
		$x3 = "DEFTARGET=`head /current/etc/opscript.txt 2>/dev/null | grepip 2>/dev/null | head -1`" fullword ascii
		$x4 = "FATAL ERROR: -x port and -n port MUST NOT BE THE SAME." fullword ascii

	condition:
		filesize <250KB and 1 of them
}
