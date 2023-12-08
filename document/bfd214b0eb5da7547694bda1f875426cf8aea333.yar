rule INDICATOR_OLE_Excel4Macros_DL1
{
	meta:
		author = "ditekSHen"
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"
		os = "windows,macos"
		filetype = "document"

	strings:
		$s1 = "Macros Excel 4.0" fullword ascii
		$s2 = { 00 4d 61 63 72 6f 31 85 00 }
		$s3 = "http" ascii
		$s4 = "file:" ascii
		$fa_exe = ".exe" ascii nocase
		$fa_scr = ".scr" ascii nocase
		$fa_dll = ".dll" ascii nocase
		$fa_bat = ".bat" ascii nocase
		$fa_cmd = ".cmd" ascii nocase
		$fa_sct = ".sct" ascii nocase
		$fa_txt = ".txt" ascii nocase
		$fa_psw = ".ps1" ascii nocase
		$fa_py = ".py" ascii nocase
		$fa_js = ".js" ascii nocase

	condition:
		uint16(0)==0xcfd0 and (3 of ($s*) and 1 of ($fa*))
}
