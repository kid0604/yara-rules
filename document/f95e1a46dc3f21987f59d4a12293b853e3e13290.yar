rule INDICATOR_OLE_EXPLOIT_CVE_2017_11882_1
{
	meta:
		description = "detects OLE documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$s2 = { 02 ce 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$s3 = "ole10native" wide nocase
		$s4 = "Root Entry" wide

	condition:
		uint16(0)==0xcfd0 and all of them
}
