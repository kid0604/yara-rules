rule EquationGroup_Toolset_Apr17_DUMPEL
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "bf42532be2d36f522dca7d3d3eb40b1d25c33d508a5a37c7e28f148945136dc6"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "dumpel -f file [-s \\\\server]" fullword ascii
		$x2 = "records will not appear in the dumped log." fullword ascii
		$x3 = "obj\\i386\\Dumpel.exe" fullword ascii
		$s13 = "DUMPEL Usage:    " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
