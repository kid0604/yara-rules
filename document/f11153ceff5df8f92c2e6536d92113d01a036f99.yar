import "pe"

rule TA17_293A_Query_XML_Code_MAL_DOC_alt_1
{
	meta:
		name = "Query_XML_Code_MAL_DOC"
		author = "other (modified by Florian Roth)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		description = "Detects malicious Microsoft Word documents containing XML code"
		os = "windows"
		filetype = "document"

	strings:
		$dir = "word/_rels/" ascii
		$dir2 = "word/theme/theme1.xml" ascii
		$style = "word/styles.xml" ascii

	condition:
		uint32(0)==0x04034b50 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd
}
