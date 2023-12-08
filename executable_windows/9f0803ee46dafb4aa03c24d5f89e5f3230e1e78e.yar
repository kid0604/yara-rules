import "pe"

rule INDICATOR_KB_CERT_5a17d5de74fd8f09df596df3123139bb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1da887a57dddd7376a18f75841559c9682f78b04"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTA FIS d.o.o." and pe.signatures[i].serial=="5a:17:d5:de:74:fd:8f:09:df:59:6d:f3:12:31:39:bb")
}
