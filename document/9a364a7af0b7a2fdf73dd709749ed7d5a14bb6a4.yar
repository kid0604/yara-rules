rule maldoc_indirect_function_call_3 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects indirect function calls in malicious documents"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$a = {FF B7 ?? ?? ?? ?? FF 57 ??}

	condition:
		$a
}
