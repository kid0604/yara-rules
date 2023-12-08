rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_2
{
	meta:
		description = "detects an obfuscated RTF variant documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$eq1 = "02ce020000000000c000000000000046" ascii nocase
		$eq2 = "equation." ascii nocase
		$eq3 = "6551754174496f4e2e33" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii
		$s1 = "4c6f61644c696272617279" ascii nocase
		$s2 = "47657450726f6341646472657373" ascii nocase
		$s3 = "55524c446f776e6c6f6164546f46696c65" ascii nocase
		$s4 = "5368656c6c45786563757465" ascii nocase
		$s5 = "4578697450726f63657373" ascii nocase

	condition:
		uint32(0)==0x74725c7b and 1 of ($eq*) and 1 of ($obj*) and 2 of ($s*)
}
