rule invalid_XObject_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/

	condition:
		$magic in (0..1024) and not $ver and all of ($attrib*)
}
