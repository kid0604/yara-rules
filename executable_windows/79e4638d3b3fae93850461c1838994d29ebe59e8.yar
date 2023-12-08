rule Predator_The_Thief : Predator_The_Thief
{
	meta:
		description = "Yara rule for Predator The Thief v2.3.5 & +"
		author = "Fumik0_"
		date = "2018/10/12"
		source = "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4D 5A }
		$hex1 = { BF 00 00 40 06 }
		$hex2 = { C6 04 31 6B }
		$hex3 = { C6 04 31 63 }
		$hex4 = { C6 04 31 75 }
		$hex5 = { C6 04 31 66 }
		$s1 = "sqlite_" ascii wide

	condition:
		$mz at 0 and all of ($hex*) and all of ($s*)
}
