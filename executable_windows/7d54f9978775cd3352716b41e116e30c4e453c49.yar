import "pe"

rule INDICATOR_KB_CERT_767436921b2698bd18400a24b01341b6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "871899843b5fd100466e351ca773dac44e936939"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and pe.signatures[i].serial=="76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6")
}
