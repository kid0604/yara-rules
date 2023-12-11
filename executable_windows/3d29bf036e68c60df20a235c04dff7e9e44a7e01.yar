import "pe"

rule INDICATOR_KB_CERT_00c79f817f082986bef3209f6723c8da97
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e2bf86dc46fca1c35f98ff84d8976be8aa0668bc"
		hash1 = "dd49651e325b04ea14733bcd676c0a1cb58ab36bf79162868ade02b396ec3ab0"
		hash2 = "823cb4b92a1266c880d917c7d6f71da37d524166287b30c0c89b6bb03c2e4b64"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Al-Faris group d.o.o." and pe.signatures[i].serial=="00:c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97")
}
