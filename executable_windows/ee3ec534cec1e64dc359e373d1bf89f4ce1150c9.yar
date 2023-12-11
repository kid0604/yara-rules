import "pe"

rule INDICATOR_KB_CERT_79e1cc0f6722e1a2c4647c21023ca4ee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "41d2f4f810a6edf42b3717cf01d4975476f63cba"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPAGETTI LTD" and pe.signatures[i].serial=="79:e1:cc:0f:67:22:e1:a2:c4:64:7c:21:02:3c:a4:ee")
}
