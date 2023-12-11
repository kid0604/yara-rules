rule maldoc_getEIP_method_1 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects maldoc using the getEIP method"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}

	condition:
		$a
}
