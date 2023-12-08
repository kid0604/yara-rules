import "pe"

rule INDICATOR_KB_CERT_00b7e0cf12e4ae50dd643a24285485602f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "744160f36ba9b0b9277c6a71bf383f1898fd6d89"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GESO LTD" and pe.signatures[i].serial=="00:b7:e0:cf:12:e4:ae:50:dd:64:3a:24:28:54:85:60:2f")
}
