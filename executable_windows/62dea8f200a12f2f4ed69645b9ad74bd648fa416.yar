import "pe"

rule EquationDrug_NetworkSniffer3
{
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "14599516381a9646cd978cf962c4f92386371040"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Corporation. All rights reserved." fullword wide
		$s1 = "IP Transport Driver" fullword wide
		$s2 = "tdip.sys" fullword wide
		$s3 = "tdip.pdb" fullword ascii

	condition:
		all of them
}
