rule INDICATOR_RTF_ThreadKit_Exploit_Builder_Document
{
	meta:
		description = "Detects vaiations of RTF documents generated by ThreadKit builder."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii
		$pat1 = /\\objupdate\\v[\\\s\n\r]/ ascii

	condition:
		uint32(0)==0x74725c7b and 2 of ($obj*) and 1 of ($pat*)
}
