rule EquationGroup_Toolset_Apr17_SlDecoder
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "b220f51ca56d9f9d7d899fa240d3328535f48184d136013fd808d8835919f9ce"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
		$x2 = "KeyLogger_Data" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
