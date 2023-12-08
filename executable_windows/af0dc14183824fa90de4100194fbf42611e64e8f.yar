import "pe"

rule EquationGroup_ProcessHide_Lp
{
	meta:
		description = "EquationGroup Malware - file ProcessHide_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Invalid flag.  Can only hide or unhide" fullword wide
		$x2 = "Process elevation failed" fullword wide
		$x3 = "Unknown error hiding process" fullword wide
		$x4 = "Invalid process links found in EPROCESS" fullword wide
		$x5 = "Unable to find SYSTEM process" fullword wide
		$x6 = "Process hidden, but EPROCESS location lost" fullword wide
		$x7 = "Invalid EPROCESS location for given ID" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them ) or (3 of them )
}
