import "pe"

rule EquationGroup_ntfltmgr
{
	meta:
		description = "EquationGroup Malware - file ntfltmgr.sys"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ntfltmgr.sys" fullword wide
		$s2 = "ntfltmgr.pdb" fullword ascii
		$s4 = "Network Filter Manager" fullword wide
		$s5 = "Corporation. All rights reserved." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
