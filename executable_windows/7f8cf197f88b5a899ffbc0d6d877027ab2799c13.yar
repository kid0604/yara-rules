import "pe"

rule INDICATOR_KB_CERT_5998b4affe2adf592e6528ff800e567c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d990d584c856bd28eab641c3c3a0f80c0b71c4d7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BEAT GOES ON LIMITED" and pe.signatures[i].serial=="59:98:b4:af:fe:2a:df:59:2e:65:28:ff:80:0e:56:7c")
}
