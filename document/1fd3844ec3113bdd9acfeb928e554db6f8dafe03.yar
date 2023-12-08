rule suspicious_creator : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		description = "Detects PDF files with suspicious creators"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"

	condition:
		$magic in (0..1024) and $header and 1 of ($creator*)
}
