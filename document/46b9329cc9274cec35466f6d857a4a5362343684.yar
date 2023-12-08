rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_4
{
	meta:
		description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = { (36|34)[0-5]35[0-5](37|35)[0-5]31[0-5](37|35)[0-5]35[0-5](36|34)[0-5]31[0-5](37|35)[0-5]34[0-5](36|34)[0-5]39[0-5](36|34)[0-5]66[0-5](36|34)[0-5]65[0-5]32[0-5]65[0-5]33[0-5]33 }
		$s2 = { (7d|5c|2b|24)[0-5](37|35)[0-5]31[0-5](37|35)[0-5]35[0-5](36|34)[0-5]31[0-5](37|35)[0-5]34[0-5](36|34)[0-5]39[0-5](36|34)[0-5]66[0-5](36|34)[0-5]65[0-5]32[0-5]65[0-5]33[0-5]33 }
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
