rule INDICATOR_OLE_ObjectPool_Embedded_Files_alt_2
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
		$fh_exe = { 2e (45|65) (58|78) (45|65) 00 }
		$fh_scr = { 2e (53|73) (43|63) (52|72) 00 }
		$fh_dll = { 2e (44|64) (4c|6c) (4c|6c) 00 }
		$fh_bat = { 2e (42|62) (41|61) (54|74) 00 }
		$fh_cmd = { 2e (43|63) (4d|6d) (44|64) 00 }
		$fh_sct = { 2e (53|73) (43|63) (54|74) 00 }
		$fh_txt = { 2e (54|74) (58|78) (54|74) 00 }
		$fh_psw = { 2e (50|70) (53|73) 31 00 }

	condition:
		uint16(0)==0xcfd0 and ( all of ($s*) or all of ($h*)) and $olepkg and (1 of ($fa*) or 1 of ($fh*))
}
