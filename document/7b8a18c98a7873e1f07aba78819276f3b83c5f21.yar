rule INDICATOR_RTF_MalVer_Objects
{
	meta:
		description = "Detects RTF documents with non-standard version and embeding one of the object mostly observed in exploit documents."
		author = "ditekSHen"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii

	condition:
		uint32(0)==0x74725c7b and (( not uint8(4)==0x66 or not uint8(5)==0x31 or not uint8(6)==0x5c) and 1 of ($obj*))
}
