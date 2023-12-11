import "pe"

rule EquationDrug_NetworkSniffer4
{
	meta:
		description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
		$s1 = "\\systemroot\\" fullword ascii
		$s2 = "RAVISENT Technologies Inc." fullword wide
		$s3 = "Created by VIONA Development" fullword wide
		$s4 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s5 = "\\device\\harddiskvolume" fullword wide
		$s7 = "ATMDKDRV.SYS" fullword wide
		$s8 = "\\Device\\%ws_%ws" fullword wide
		$s9 = "\\DosDevices\\%ws" fullword wide
		$s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
		$s11 = "\\Device\\%ws" fullword wide
		$s13 = "CineMaster C 1.1 WDM" fullword wide

	condition:
		all of them
}
