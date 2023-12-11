rule INDICATOR_OLE_RemoteTemplate
{
	meta:
		description = "Detects XML relations where an OLE object is refrencing an external target in dropper OOXML documents"
		author = "ditekSHen"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$olerel = "relationships/oleObject" ascii
		$target1 = "Target=\"http" ascii
		$target2 = "Target=\"file" ascii
		$mode = "TargetMode=\"External" ascii

	condition:
		$olerel and $mode and 1 of ($target*)
}
