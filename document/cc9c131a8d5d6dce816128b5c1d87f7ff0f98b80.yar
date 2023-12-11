rule maldoc_indirect_function_call_2 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects indirect function calls in malicious documents"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}

	condition:
		for any i in (1..#a) : (( uint8(@a[i]+2)== uint8(@a[i]+8)) and ( uint8(@a[i]+3)== uint8(@a[i]+9)) and ( uint8(@a[i]+4)== uint8(@a[i]+10)) and ( uint8(@a[i]+5)== uint8(@a[i]+11)))
}
