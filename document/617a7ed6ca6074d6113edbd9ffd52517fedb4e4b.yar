rule invalid_trailer_structure : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		description = "Detects PDF files with invalid trailer structure"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
		$reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

	condition:
		$magic in (0..1024) and not $reg0 and not $reg1
}
