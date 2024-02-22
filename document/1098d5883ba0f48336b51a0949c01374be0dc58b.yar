rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_1_alt_3
{
	meta:
		description = "Detects RTF documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = { 32[0-30](43|63)[0-30](45|65)[0-30]30[0-30]32[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30](43|63)[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]30[0-30]34[0-30]36}
		$s2 = "52006f006f007400200045006e00740072007900" ascii nocase
		$s3 = "\\bin0" ascii nocase
		$ole = { (64|44)[0-20]30[0-20](63|43)[0-20](66|46)[0-20]31[0-20]31[0-20](65|45)[0-20]30[0-20](61|41)[0-20]31[0-20](62|42)[0-20]31[0-20]31[0-20](61|41) }
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii

	condition:
		uint32(0)==0x74725c7b and 2 of ($s*) and $ole and 2 of ($obj*)
}
