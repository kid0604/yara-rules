rule EquationGroup_tmpwatch
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-09"
		hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
		$s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii

	condition:
		( filesize <1KB and 1 of them )
}
