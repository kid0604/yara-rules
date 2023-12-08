import "pe"

rule Equation_Kaspersky_EquationDrugInstaller
{
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$s0 = "\\system32\\win32k.sys" fullword wide
		$s1 = "ALL_FIREWALLS" fullword ascii
		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide

	condition:
		($mz at 0) and filesize <500000 and all of ($s*) and 5 of ($x*)
}
