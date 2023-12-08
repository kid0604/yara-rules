import "pe"

rule INDICATOR_KB_CERT_00e130d3537e0b7a4dda47b4d6f95f9481
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "89f9786c8cb147b1dd7aa0eb871f51210550c6f4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xBC\\x8A\\xE6\\x96\\xAF\\xE8\\x89\\xBE\\xE4\\xBC\\x8A\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92" and pe.signatures[i].serial=="00:e1:30:d3:53:7e:0b:7a:4d:da:47:b4:d6:f9:5f:94:81")
}
