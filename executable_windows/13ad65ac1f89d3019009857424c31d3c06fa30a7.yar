rule Equation_Kaspersky_EquationDrugInstaller_alt_1
{
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\system32\\win32k.sys" wide
		$s1 = "ALL_FIREWALLS" fullword ascii
		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500000 and all of ($s*) and 5 of ($x*)
}
