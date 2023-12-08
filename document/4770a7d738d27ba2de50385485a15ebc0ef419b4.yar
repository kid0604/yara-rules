rule docx_macro : mail
{
	meta:
		description = "Detects the presence of VBA macros in DOCX files"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$header = "PK"
		$vbaStrings = "word/vbaProject.bin" nocase

	condition:
		$header at 0 and $vbaStrings
}
