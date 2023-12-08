rule SUSP_OneNote_RTLO_Character_Feb23
{
	meta:
		description = "Presence of RTLO Unicode Character in a OneNote file with embedded files"
		author = "delivr.to"
		date = "2023-02-17"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
		$fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
		$rtlo = { 00 2E 20 }

	condition:
		filesize <5MB and ($one at 0) and $fdso and $rtlo
}
