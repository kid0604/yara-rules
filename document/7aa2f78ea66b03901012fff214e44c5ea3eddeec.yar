rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_1
{
	meta:
		description = "Detects RTF documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "02ce020000000000c000000000000046" ascii nocase
		$s2 = "52006f006f007400200045006e00740072007900" ascii nocase
		$ole1 = "d0cf11e0a1b11ae1" ascii nocase
		$olex = { (64|44)[0-1]30[0-1](63|43)[0-1](66|46)[0-1]31[0-1]31[0-1](65|45)[0-1]30[0-1](61|41)[0-1]31[0-1](62|42)[0-1]31[0-1]31[0-1](61|41) }
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii

	condition:
		uint32(0)==0x74725c7b and all of ($s*) and 1 of ($ole*) and 2 of ($obj*)
}
