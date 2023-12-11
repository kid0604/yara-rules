rule suspicious_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		description = "Detects suspicious JavaScript in PDF files"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /
		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"

	condition:
		$magic in (0..1024) and all of ($attrib*) and 2 of ($js*)
}
