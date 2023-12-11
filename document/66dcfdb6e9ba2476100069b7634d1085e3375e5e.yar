rule embed_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$embed = /\/EmbeddedFiles/
		$ver = /%PDF-1\.[3-9]/

	condition:
		$magic in (0..1024) and $embed and not $ver
}
