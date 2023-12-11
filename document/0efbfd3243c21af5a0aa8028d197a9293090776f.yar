rule suspicious_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		description = "Detects suspicious PDF files with incorrect version format"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/

	condition:
		$magic in (0..1024) and not $ver
}
