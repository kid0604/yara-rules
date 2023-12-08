import "pe"

rule EquationGroup_EquationDrug_mstcp32
{
	meta:
		description = "EquationGroup Malware - file mstcp32.sys"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		modified = "2023-01-06"
		hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mstcp32.sys" fullword wide
		$s2 = "p32.sys" fullword ascii
		$s3 = "\\Registry\\User\\CurrentUser\\" wide
		$s4 = "\\DosDevices\\%ws" wide
		$s5 = "\\Device\\%ws_%ws" wide
		$s6 = "sys\\mstcp32.dbg" fullword ascii
		$s7 = "%ws%03d%ws%wZ" fullword wide
		$s8 = "TCP/IP driver" fullword wide
		$s9 = "\\Device\\%ws" wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 7 of them ) or ( all of them )
}
