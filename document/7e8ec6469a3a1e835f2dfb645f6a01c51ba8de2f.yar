rule maldoc_getEIP_method_4 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects malicious document using the getEIP method 4"
		os = "windows"
		filetype = "document"

	strings:
		$a1 = {D9 EE D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
		$a2 = {D9 EE 9B D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}

	condition:
		any of them
}
