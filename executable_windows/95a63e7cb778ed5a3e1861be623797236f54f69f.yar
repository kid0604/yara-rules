import "pe"

rule INDICATOR_KB_CERT_7e89b9df006bd1aa4c48d865039634ca
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "63ad44acaa7cd7f8249423673fbf3c3273e7b2dc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dummy" and pe.signatures[i].serial=="7e:89:b9:df:00:6b:d1:aa:4c:48:d8:65:03:96:34:ca")
}
