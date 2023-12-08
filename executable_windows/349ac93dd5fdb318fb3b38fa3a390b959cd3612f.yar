import "pe"

rule INDICATOR_KB_CERT_c54cccff8acceb9654b6f585e2442ef7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "416c79fccc5f42260cd227fd831b001aca14bf0d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eadbebdebcc" and pe.signatures[i].serial=="c5:4c:cc:ff:8a:cc:eb:96:54:b6:f5:85:e2:44:2e:f7")
}
