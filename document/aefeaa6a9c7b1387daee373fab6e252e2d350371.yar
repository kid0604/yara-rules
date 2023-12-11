rule INDICATOR_RTF_EXPLOIT_CVE_2017_8759_2
{
	meta:
		description = "detects CVE-2017-8759 weaponized RTF documents."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$clsid1 = { 88 d9 6a 0c f1 92 11 d4 a6 5f 00 40 96 32 51 e5 }
		$clsid2 = "88d96a0cf19211d4a65f0040963251e5" ascii nocase
		$clsid3 = "4d73786d6c322e534158584d4c5265616465722e" ascii nocase
		$clsid4 = "Msxml2.SAXXMLReader." ascii nocase
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\objclass htmlfile" ascii
		$soap1 = "c7b0abec197fd211978e0000f8757e" ascii nocase

	condition:
		uint32(0)==0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and (2 of ($obj*) or 1 of ($soap*))
}
