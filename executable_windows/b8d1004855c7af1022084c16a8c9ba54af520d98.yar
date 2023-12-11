import "pe"

rule INDICATOR_KB_CERT_009245d1511923f541844faa3c6bfebcbe
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "509cbd2cd38ae03461745c7d37f6bbe44c6782cf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEHTEH d.o.o.," and pe.signatures[i].serial=="00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be")
}
