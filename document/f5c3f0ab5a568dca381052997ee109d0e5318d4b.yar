rule INDICATOR_OOXML_Excel4Macros_AutoOpenHidden
{
	meta:
		author = "ditekSHen"
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet auto_open and state hidden"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"
		os = "windows,macos"
		filetype = "document"

	strings:
		$s1 = "state=\"veryhidden\"" ascii nocase
		$s2 = "<definedName name=\"_xlnm.Auto_Open" ascii nocase

	condition:
		uint32(0)==0x6d783f3c and all of them
}
