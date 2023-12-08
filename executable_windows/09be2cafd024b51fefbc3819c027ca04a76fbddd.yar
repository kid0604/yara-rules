import "pe"

rule INDICATOR_KB_CERT_48ce01ac7e137f4313cc5723af817da0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "8f594f2e0665ffd656160aac235d8c490059a9cc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ET HOMES LTD" and pe.signatures[i].serial=="48:ce:01:ac:7e:13:7f:43:13:cc:57:23:af:81:7d:a0")
}
