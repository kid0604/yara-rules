rule EquationGroup_scripme
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file scripme"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "a1adf1c1caad96e7b7fd92cbf419c4cfa13214e66497c9e46ec274a487cd098a"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "running \\\"tcpdump -n -n\\\", on the environment variable \\$INTERFACE, scripted" fullword ascii
		$x2 = "Cannot read $opetc/scripme.override -- are you root?" ascii
		$x3 = "$ENV{EXPLOIT_SCRIPME}" ascii
		$x4 = "$opetc/scripme.override" ascii

	condition:
		( filesize <30KB and 1 of them )
}
