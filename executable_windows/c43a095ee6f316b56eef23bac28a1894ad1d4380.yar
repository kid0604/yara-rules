rule EquationGroup_Toolset_Apr17_yak
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "66ff332f84690642f4e05891a15bf0c9783be2a64edb2ef2d04c9205b47deb19"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "-xd = dump archive data & store in scancodes.txt" fullword ascii
		$x2 = "-------- driver start token -------" fullword wide
		$x3 = "-------- keystart token -------" fullword wide
		$x4 = "-xta = same as -xt but show special chars & store in keys_all.txt" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and 2 of them )
}
