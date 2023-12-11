import "pe"

rule INDICATOR_KB_CERT_0cf1ed2a6ff4bee621efdf725ea174b7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e33dc0787099d92a712894cfef2aaba3f0d65359"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and pe.signatures[i].serial=="0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7")
}
