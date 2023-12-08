import "pe"

rule INDICATOR_KB_CERT_234bf4ef892df307373638014b35ab37
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "348f7e395c77e29c1e17ef9d9bd24481657c7ae7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="23:4b:f4:ef:89:2d:f3:07:37:36:38:01:4b:35:ab:37")
}
