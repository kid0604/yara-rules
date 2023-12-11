import "pe"

rule INDICATOR_KB_CERT_00f097e59809ae2e771b7b9ae5fc3408d7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "22ad7df275c8b5036ea05b95ce5da768049bd2b21993549eed3a8a5ada990b1e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and pe.signatures[i].serial=="00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7")
}
