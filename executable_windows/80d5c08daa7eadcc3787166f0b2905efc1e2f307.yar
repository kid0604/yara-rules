import "pe"

rule Foudre_Backdoor_Component_1
{
	meta:
		description = "Detects Foudre Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Nbqbt6"
		date = "2017-08-01"
		modified = "2023-01-07"
		hash1 = "7c6206eaf0c5c9c6c8d8586a626b49575942572c51458575e51cba72ba2096a4"
		hash2 = "db605d501d3a5ca2b0e3d8296d552fbbf048ee831be21efca407c45bf794b109"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 50 72 6F 6A 65 63 74 31 2E 64 6C 6C 00 44 31 }
		$s2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" fullword wide
		$s3 = "C:\\Documents and Settings\\All Users\\" wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (3 of them ) or (2 of them and pe.exports("D1")))
}
