import "pe"

rule TA17_293A_Query_XML_Code_MAL_DOC_PT_2
{
	meta:
		name = "Query_XML_Code_MAL_DOC_PT_2"
		author = "other (modified by Florian Roth)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		description = "Detects malicious documents containing XML code"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$dir1 = "word/_rels/settings.xml.rels"
		$bytes = {8c 90 cd 4e eb 30 10 85 d7}

	condition:
		uint32(0)==0x04034b50 and $dir1 and $bytes
}
