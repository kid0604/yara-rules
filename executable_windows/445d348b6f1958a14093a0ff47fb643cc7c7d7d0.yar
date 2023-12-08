rule EquationGroup_calserver
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file calserver"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "048625e9a0ca46d7fe221e262c8dd05e7a5339990ffae2fb65a9b0d705ad6099"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "usage: %s <host> <port> e <contents of a local file to be executed on target>" fullword ascii
		$x2 = "Writing your %s to target." fullword ascii
		$x3 = "(e)xploit, (r)ead, (m)ove and then write, (w)rite" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 1 of them )
}
