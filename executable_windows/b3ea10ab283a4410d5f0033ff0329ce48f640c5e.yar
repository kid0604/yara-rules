import "pe"

rule EquationDrug_FileSystem_Filter
{
	meta:
		description = "EquationDrug - Filesystem filter driver – volrec.sys, scsi2mgr.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "volrec.sys" fullword wide
		$s1 = "volrec.pdb" fullword ascii
		$s2 = "Volume recognizer driver" fullword wide

	condition:
		all of them
}
