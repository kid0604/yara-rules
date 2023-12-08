rule INDICATOR_RTF_EXPLOIT_CVE_2017_8759_1
{
	meta:
		description = "detects CVE-2017-8759 weaponized RTF documents."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$clsid2 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$clsid3 = "0003000000000000c000000000000046" ascii nocase
		$clsid4 = "4f4c45324c696e6b" ascii nocase
		$clsid5 = "OLE2Link" ascii nocase
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$s1 = "wsdl=http" wide
		$s2 = "METAFILEPICT" ascii
		$s3 = "INCLUDEPICTURE \"http" ascii
		$s4 = "!This program cannot be run in DOS mode" ascii

	condition:
		uint32(0)==0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and 2 of ($s*)
}
