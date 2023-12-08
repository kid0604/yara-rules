rule INDICATOR_OLE_ObjectPool_Embedded_Files
{
	meta:
		description = "Detects OLE documents with ObjectPool OLE storage and embed suspicous excutable files"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "ObjectPool" fullword wide
		$s2 = "Ole10Native" fullword wide
		$s3 = "Root Entry" fullword wide
		$h1 = { 4f 00 62 00 6a 00 65 00 63 00 74 00 50 00 6f 00 6f 00 6c 00 }
		$h2 = { 4f 00 6c 00 65 00 31 00 30 00 4e 00 61 00 74 00 69 00 76 00 65 00 }
		$h3 = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 }
		$olepkg = { 00 00 00 0c 00 03 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$fa_exe = ".exe" ascii nocase
		$fa_scr = ".scr" ascii nocase
		$fa_dll = ".dll" ascii nocase
		$fa_bat = ".bat" ascii nocase
		$fa_cmd = ".cmd" ascii nocase
		$fa_sct = ".sct" ascii nocase
		$fa_txt = ".txt" ascii nocase
		$fa_psw = ".ps1" ascii nocase

	condition:
		uint16(0)==0xcfd0 and ( all of ($s*) or all of ($h*)) and $olepkg and 1 of ($fa*)
}
