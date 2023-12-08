rule suspicious_producer : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		description = "Detects PDF files with suspicious producers"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"

	condition:
		$magic in (0..1024) and $header and 1 of ($producer*)
}
