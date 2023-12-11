rule INDICATOR_OLE_Suspicious_MITRE_T1117
{
	meta:
		description = "Detects MITRE technique T1117 in OLE documents"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "scrobj.dll" ascii nocase
		$s2 = "regsvr32" ascii nocase
		$s3 = "JyZWdzdnIzMi5leGU" ascii
		$s4 = "HNjcm9iai5kbGw" ascii

	condition:
		uint16(0)==0xcfd0 and 2 of them
}
