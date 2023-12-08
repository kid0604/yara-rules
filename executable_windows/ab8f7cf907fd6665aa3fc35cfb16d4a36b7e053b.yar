import "pe"

rule INDICATOR_KB_CERT_62165b335c13a1a847ce9acff2b29368
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c4cfd244d5148c5b03cac093d49af723252b643c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "t55555Prh" and pe.signatures[i].serial=="62:16:5b:33:5c:13:a1:a8:47:ce:9a:cf:f2:b2:93:68")
}
