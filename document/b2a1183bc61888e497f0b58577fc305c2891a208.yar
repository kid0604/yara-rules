rule INDICATOR_OLE_MetadataCMD
{
	meta:
		description = "Detects OLE documents with Windows command-line utilities commands (certutil, powershell, etc.) stored in the metadata (author, last modified by, etc.)."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$cmd1 = { 00 1E 00 00 00 [1-4] 00 00 (63|43) (6D|4D) (64|44) (00|20) }
		$cmd2 = { 00 1E 00 00 00 [1-4] 00 00 (6D|4D) (73|53) (68|48) (74|54) (61|41) (00|20) }
		$cmd3 = { 00 1E 00 00 00 [1-4] 00 00 (77|57) (73|53) (63|43) (72|52) (69|49) (70|50) (74|54) (00|20) }
		$cmd4 = { 00 1E 00 00 00 [1-4] 00 00 (63|42) (65|45) (72|52) (74|54) (75|55) (74|54) (69|49) (6C|4C) (00|20) }
		$cmd5 = { 00 1E 00 00 00 [1-4] 00 00 (70|50) (6F|4F) (77|57) (65|45) (72|52) (73|43) (68|48) (65|45) (6C|4C) (6C|4C) (00|20) }
		$cmd6 = { 00 1E 00 00 00 [1-4] 00 00 (6E|4E) (65|45) (74|54) 2E (77|57) (65|45) (62|42) (63|43) (6C|4C) (69|49) (65|45) (6E|4E) (74|54) (00|20) }

	condition:
		uint16(0)==0xcfd0 and any of them
}
