import "pe"

rule INDICATOR_KB_CERT_00d627f1000d12485995514bfbdefc55d9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5fac3a6484e93f62686e12de3611f7a5251009d541f65e8fe17decc780148052"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and pe.signatures[i].serial=="00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9")
}
