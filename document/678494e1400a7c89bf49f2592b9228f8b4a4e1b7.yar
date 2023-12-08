rule suspicious_obfuscation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		description = "Detects suspicious obfuscation in PDF files"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/

	condition:
		$magic in (0..1024) and #reg>5
}
