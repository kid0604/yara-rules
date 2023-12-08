import "pe"

rule INDICATOR_KB_CERT_6abc3555becca0bc4b6987ccc2ea42b5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a36c75dd80d34020df5632c2939e82d39d2dca64"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jwkwjaagoh" and pe.signatures[i].serial=="6a:bc:35:55:be:cc:a0:bc:4b:69:87:cc:c2:ea:42:b5")
}
