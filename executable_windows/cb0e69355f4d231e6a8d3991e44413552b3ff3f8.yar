import "pe"

rule INDICATOR_KB_CERT_5172caa2119185382343fcbe09c43bee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "fd9b3f6b0eb9bd9baf7cbdc79ae7979b7ddad770"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aefcdac" and pe.signatures[i].serial=="51:72:ca:a2:11:91:85:38:23:43:fc:be:09:c4:3b:ee")
}
