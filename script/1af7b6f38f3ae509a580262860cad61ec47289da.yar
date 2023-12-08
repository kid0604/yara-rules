rule EquationGroup_Toolset_Apr17_DS_ParseLogs
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "0228691d63038b072cdbf50782990d505507757efbfa87655bb2182cf6375956"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
		$x2 = "* Capture header not found at start of buffer" fullword wide
		$x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
