import "pe"

rule EquationDrug_VolRec_Driver
{
	meta:
		description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "msrstd.sys" fullword wide
		$s1 = "msrstd.pdb" fullword ascii
		$s2 = "msrstd driver" fullword wide

	condition:
		all of them
}
