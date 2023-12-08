import "pe"

rule INDICATOR_KB_CERT_00fe41941464b9992a69b7317418ae8eb7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ef4da71810fb92e942446ee1d9b5f38fea49628e0d8335a485f328fcef7f1a20"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Milsean Software Limited" and pe.signatures[i].serial=="00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7")
}
