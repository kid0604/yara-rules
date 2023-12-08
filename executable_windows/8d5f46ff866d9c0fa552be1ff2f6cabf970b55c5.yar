import "pe"

rule EquationDrug_NetworkSniffer5
{
	meta:
		description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "09399b9bd600d4516db37307a457bc55eedcbd17"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s2 = "atmdkdrv.sys" fullword wide
		$s4 = "\\Device\\%ws_%ws" fullword wide
		$s5 = "\\DosDevices\\%ws" fullword wide
		$s6 = "\\Device\\%ws" fullword wide

	condition:
		all of them
}
