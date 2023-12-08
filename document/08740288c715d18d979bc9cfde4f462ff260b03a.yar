rule INDICATOR_XML_WebRelFrame_RemoteTemplate
{
	meta:
		description = "Detects XML web frame relations refrencing an external target in dropper OOXML documents"
		author = "ditekSHen"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$target1 = "/frame\" Target=\"http" ascii nocase
		$target2 = "/frame\" Target=\"file" ascii nocase
		$mode = "TargetMode=\"External" ascii

	condition:
		uint32(0)==0x6d783f3c and (1 of ($target*) and $mode)
}
