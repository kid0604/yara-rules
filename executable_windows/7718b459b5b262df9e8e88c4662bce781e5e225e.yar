import "pe"

rule INDICATOR_KB_CERT_29e8e993d2406454b6b18cb377471bc6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0fb38235366b0ba534a6f81c02d9a67555235e07"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MONDIAL MONTERO SP Z O O" and pe.signatures[i].serial=="29:e8:e9:93:d2:40:64:54:b6:b1:8c:b3:77:47:1b:c6")
}
