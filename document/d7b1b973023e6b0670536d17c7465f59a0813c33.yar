rule maldoc_OLE_file_magic_number : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects OLE file magic number in documents"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$a = {D0 CF 11 E0}

	condition:
		$a
}
