rule INDICATOR_OLE_Excel4Macros_DL3
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"
		os = "windows,macos"
		filetype = "document"

	strings:
		$a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 }
		$a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }
		$a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 }
		$a6 = "auto_open" ascii nocase
		$a7 = "auto_close" ascii nocase
		$s1 = "* #,##0" ascii
		$s2 = "URLMon" ascii
		$s3 = "DownloadToFileA" ascii
		$s4 = "DllRegisterServer" ascii

	condition:
		uint16(0)==0xcfd0 and 1 of ($a*) and all of ($s*) and #s1>3
}
