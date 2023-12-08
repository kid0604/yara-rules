rule maldoc_indirect_function_call_1 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects indirect function calls in malicious documents"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$a = {FF 75 ?? FF 55 ??}

	condition:
		for any i in (1..#a) : ( uint8(@a[i]+2)== uint8(@a[i]+5))
}
