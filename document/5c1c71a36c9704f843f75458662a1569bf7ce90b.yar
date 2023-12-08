rule SUSP_OneNote_Win_Script_Encoding_Feb23
{
	meta:
		description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
		author = "delivr.to"
		date = "2023-02-19"
		score = 60
		os = "windows"
		filetype = "document"

	strings:
		$one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
		$fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
		$wse = { 23 40 7E 5E }

	condition:
		filesize <5MB and ($one at 0) and $fdso and $wse
}
