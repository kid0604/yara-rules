rule SUSP_Macro_Sheet_Obfuscated_Char
{
	meta:
		description = "Finding hidden/very-hidden macros with many CHAR functions"
		author = "DissectMalware"
		date = "2020-04-07"
		score = 65
		hash1 = "0e9ec7a974b87f4c16c842e648dd212f80349eecb4e636087770bc1748206c3b"
		reference = "https://twitter.com/DissectMalware/status/1247595433305800706"
		os = "windows"
		filetype = "document"

	strings:
		$ole_marker = {D0 CF 11 E0 A1 B1 1A E1}
		$s1 = "Excel" fullword ascii
		$macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
		$macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
		$char_func = {06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1E 3D  00 41 6F 00}

	condition:
		$ole_marker at 0 and 1 of ($macro_sheet_h*) and #char_func>10 and $s1
}
