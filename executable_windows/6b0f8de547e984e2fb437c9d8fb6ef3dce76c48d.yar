import "pe"

rule INDICATOR_KB_CERT_00d08d83ff118df3777e371c5c482cce7b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8a1bcf92ea961b8bc8817b0630f34607ccb5bff2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMO-K Limited Liability Company" and pe.signatures[i].serial=="00:d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b")
}
