rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_3
{
	meta:
		description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$ole1 = "4f006c006500310030004e00410054004900760065" ascii nocase
		$ole2 = { (3666|3466) (3663|3463) (3635|3435) 3331 3330 (3665|3465) (3631|3431) (3734|3534) (3639|3439) (3736|3536) (3635|3435) }
		$clsid1 = "2ce020000000000c000000000000046" ascii nocase
		$clsid2 = { 32 (43|63) (45|65) 30 32 30 30 30 30 30 30 30 30 30 30 (43|63) 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36 }
		$re = "52006f006f007400200045006e00740072007900" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (1 of ($ole*) and 1 of ($clsid*) and $re and 1 of ($obj*))
}
