import "pe"

rule INDICATOR_KB_CERT_4bec555c48aada75e83c09c9ad22dc7c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "a2be2ab16e3020ddbff1ff37dbfe2d736be7a0d5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xD0\\x92\\xE5\\xB1\\x81\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE5\\x90\\x89\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE4\\xB8\\x9D\\xE5\\xB1\\x81" and pe.signatures[i].serial=="4b:ec:55:5c:48:aa:da:75:e8:3c:09:c9:ad:22:dc:7c")
}
