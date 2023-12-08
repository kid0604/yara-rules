rule EquationGroup_gr_alt_1
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "d3cd725affd31fa7f0e2595f4d76b09629918612ef0d0307bb85ade1c3985262"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "if [ -f /tmp/tmpwatch ] ; then" fullword ascii
		$s2 = "echo \"bailing. try a different name\"" fullword ascii

	condition:
		( filesize <1KB and all of them )
}
