import "pe"

rule INDICATOR_KB_CERT_03d433fdc2469e9fd878c80bc0545147
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "64e90267e6359060a8669aebb94911e92bd0c5f3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xEC\\xA3\\xBC\\xEC\\x8B\\x9D\\xED\\x9A\\x8C\\xEC\\x82\\xAC \\xEC\\x97\\x98\\xEB\\xA6\\xAC\\xEC\\x8B\\x9C\\xEC\\x98\\xA8\\xEB\\x9E\\xA9" and pe.signatures[i].serial=="03:d4:33:fd:c2:46:9e:9f:d8:78:c8:0b:c0:54:51:47")
}
