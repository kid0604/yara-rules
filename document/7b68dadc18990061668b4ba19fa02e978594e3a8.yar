rule INDICATOR_RTF_Embedded_Excel_SheetMacroEnabled
{
	meta:
		description = "Detects RTF documents embedding an Excel sheet with macros enabled. Observed in exploit followed by dropper behavior"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$ex1 = "457863656c2e53686565744d6163726f456e61626c65642e" ascii nocase
		$ex2 = "0002083200000000c000000000000046" ascii nocase
		$ex3 = "Excel.SheetMacroEnabled." ascii
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (1 of ($ex*) and 1 of ($ole*) and 2 of ($obj*))
}
