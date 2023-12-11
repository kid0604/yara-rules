import "pe"

rule INDICATOR_KB_CERT_00e9a1e07314bc2f2d51818454b63e5829
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3a146f3c0fc17b9df14bd127ebf12b15a5a1a011"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "iWLiYpLtpOlZYGmysAZkhz" and pe.signatures[i].serial=="00:e9:a1:e0:73:14:bc:2f:2d:51:81:84:54:b6:3e:58:29")
}
