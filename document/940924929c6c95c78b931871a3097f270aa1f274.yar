rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_4_alt_1
{
	meta:
		description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = { (36|34)[0-50]35[0-50](37|35)[0-50]31[0-50](37|35)[0-50]35[0-50](36|34)[0-50]31[0-50](37|35)[0-50]34[0-50](36|34)[0-50]39[0-50](36|34)[0-50]66[0-50](36|34)[0-50]65[0-50]32[0-50]65[0-50]33[0-50]33 }
		$s2 = { (7d|5c|2b|24)[0-50](37|35)[0-50]31[0-50](37|35)[0-50]35[0-50](36|34)[0-50]31[0-50](37|35)[0-50]34[0-50](36|34)[0-50]39[0-50](36|34)[0-50]66[0-50](36|34)[0-50]65[0-50]32[0-50]65[0-50]33[0-50]33 }
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (1 of ($s*) and 1 of ($obj*))
}
