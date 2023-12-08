rule suspicious_title : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		description = "Detects PDF files with suspicious titles"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"

	condition:
		$magic in (0..1024) and $header and 1 of ($title*)
}
