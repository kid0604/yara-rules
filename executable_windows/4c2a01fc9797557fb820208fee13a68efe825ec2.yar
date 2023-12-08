import "pe"

rule INDICATOR_KB_CERT_0ddce8cdc91b5b649bb4b45ffbba6c6c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "23c446940a9cdc9f502b92d7928e3b3fde6d3735"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and pe.signatures[i].serial=="0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c")
}
