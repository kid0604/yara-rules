rule maldoc_API_hashing : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects maldoc API hashing"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
		$a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}

	condition:
		any of them
}
