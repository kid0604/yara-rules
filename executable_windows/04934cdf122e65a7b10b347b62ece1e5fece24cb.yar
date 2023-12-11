import "pe"

rule INDICATOR_KB_CERT_3a9bdec10e00e780316baaebfe7a772c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "981b95ffcb259862e7461bc58516d7785de91a8a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PLAN ALPHA LIMITED" and pe.signatures[i].serial=="3a:9b:de:c1:0e:00:e7:80:31:6b:aa:eb:fe:7a:77:2c")
}
