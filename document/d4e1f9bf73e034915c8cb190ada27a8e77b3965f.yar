rule INDICATOR_XML_LegacyDrawing_AutoLoad_Document
{
	meta:
		description = "detects AutoLoad documents using LegacyDrawing"
		author = "ditekSHen"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$s1 = "<legacyDrawing r:id=\"" ascii
		$s2 = "<oleObject progId=\"" ascii
		$s3 = "autoLoad=\"true\"" ascii

	condition:
		uint32(0)==0x6d783f3c and all of ($s*)
}
