rule JBIG2_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$js = /\/JBIG2Decode/
		$ver = /%PDF-1\.[4-9]/

	condition:
		$magic in (0..1024) and $js and not $ver
}
