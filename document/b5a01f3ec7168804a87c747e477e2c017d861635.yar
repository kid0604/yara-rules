import "pe"

rule info_1805_14335
{
	meta:
		description = "info_1805.xls"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
		date = "2022-09-12"
		hash1 = "e598b9700e13f2cb1c30c6d9230152ed5716a6d6e25db702576fefeb6638005e"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "32.exe" fullword ascii
		$s2 = "System32\\X" fullword ascii
		$s3 = "DocumentOwnerPassword" fullword wide
		$s4 = "DocumentUserPassword" fullword wide
		$s5 = "t\"&\"t\"&\"p\"&\"s:\"&\"//lo\"&\"pe\"&\"sp\"&\"ub\"&\"li\"&\"ci\"&\"da\"&\"de.c\"&\"o\"&\"m/cgi-bin/e\"&\"5R\"&\"5o\"&\"G4\"&\"" ascii
		$s6 = "UniresDLL" fullword ascii
		$s7 = "OEOGAJPGJPAG" fullword ascii
		$s8 = "\\Windows\\" fullword ascii
		$s9 = "_-* #,##0.00_-;\\-* #,##0.00_-;_-* \"-\"??_-;_-@_-" fullword ascii
		$s10 = "_-* #,##0_-;\\-* #,##0_-;_-* \"-\"_-;_-@_-" fullword ascii
		$s11 = "_-;_-* \"" fullword ascii
		$s12 = "^{)P -z)" fullword ascii
		$s13 = "ResOption1" fullword ascii
		$s14 = "DocumentSummaryInformation" fullword wide
		$s15 = "Root Entry" fullword wide
		$s16 = "SummaryInformation" fullword wide
		$s17 = "A\",\"JJCCBB\"" fullword ascii
		$s18 = "Excel 4.0" fullword ascii
		$s19 = "Microsoft Print to PDF" fullword wide
		$s20 = "\"_-;\\-* #,##0.00\\ \"" fullword wide

	condition:
		uint16(0)==0xcfd0 and filesize <200KB and all of them
}
