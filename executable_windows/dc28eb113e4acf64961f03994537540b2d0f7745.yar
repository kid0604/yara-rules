import "pe"

rule INDICATOR_KB_CERT_adbb8aebf8b53c6713abaca38be9bf0a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9f9b9f5a85d3005e4c613b6c2ba20b6d5d388645"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Konstant LLC" and (pe.signatures[i].serial=="ad:bb:8a:eb:f8:b5:3c:67:13:ab:ac:a3:8b:e9:bf:0a" or pe.signatures[i].serial=="00:ad:bb:8a:eb:f8:b5:3c:67:13:ab:ac:a3:8b:e9:bf:0a"))
}
