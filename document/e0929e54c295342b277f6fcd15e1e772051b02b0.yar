rule INDICATOR_OLE_Excel4Macros_DL2
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"
		os = "windows,macos"
		filetype = "document"

	strings:
		$e1 = "Macros Excel 4.0" ascii
		$e2 = { 00 4d 61 63 72 6f 31 85 00 }
		$a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }
		$a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a6 = "auto_open" ascii nocase
		$a7 = "auto_close" ascii nocase
		$x1 = "* #,##0" ascii
		$x2 = "=EXEC(CHAR(" ascii
		$x3 = "-w 1 stARt`-s" ascii nocase
		$x4 = ")&CHAR(" ascii
		$x5 = "Reverse" fullword ascii

	condition:
		uint16(0)==0xcfd0 and (1 of ($e*) and 1 of ($a*) and (#x1>3 or 2 of ($x*)))
}
