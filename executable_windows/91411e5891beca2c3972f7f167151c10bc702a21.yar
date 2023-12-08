import "pe"

rule INDICATOR_KB_CERT_0ed8ade5d73b73dade6943d557ff87e5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "9bbd8476bf8b62be738437af628d525895a2c9c9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rumikon LLC" and pe.signatures[i].serial=="0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5")
}
