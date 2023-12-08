rule INDICATOR_OOXML_Excel4Macros_EXEC
{
	meta:
		author = "ditekSHen"
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"
		os = "windows,macos"
		filetype = "document"

	strings:
		$ms = "<xm:macrosheet" ascii nocase
		$s1 = ">FORMULA.FILL(" ascii nocase
		$s2 = ">REGISTER(" ascii nocase
		$s3 = ">EXEC(" ascii nocase
		$s4 = ">RUN(" ascii nocase

	condition:
		uint32(0)==0x6d783f3c and $ms and (2 of ($s*) or ($s3))
}
