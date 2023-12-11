import "pe"

rule INDICATOR_EXE_Packed_Cassandra
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Cassandra/CyaX"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AntiEM" fullword ascii wide
		$s2 = "AntiSB" fullword ascii wide
		$s3 = "Antis" fullword ascii wide
		$s4 = "XOR_DEC" fullword ascii wide
		$s5 = "StartInject" fullword ascii wide
		$s6 = "DetectGawadaka" fullword ascii wide
		$c1 = "CyaX-Sharp" ascii wide
		$c2 = "CyaX_Sharp" ascii wide
		$c3 = "CyaX-PNG" ascii wide
		$c4 = "CyaX_PNG" ascii wide
		$pdb = "\\CyaX\\obj\\Debug\\CyaX.pdb" ascii wide

	condition:
		( uint16(0)==0x5a4d and (4 of ($s*) or 2 of ($c*) or $pdb)) or (7 of them )
}
