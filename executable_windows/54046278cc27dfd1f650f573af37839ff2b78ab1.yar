import "pe"

rule INDICATOR_KB_CERT_02d17fbf4869f23fea43c7863902df93
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d336ff8d8ccb771943a70bb4ba11239fb71beca5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Windows" and pe.signatures[i].serial=="02:d1:7f:bf:48:69:f2:3f:ea:43:c7:86:39:02:df:93")
}
