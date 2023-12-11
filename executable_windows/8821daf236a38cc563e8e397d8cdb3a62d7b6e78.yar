import "pe"

rule INDICATOR_KB_CERT_1afd1491d52f89ba41fa6c0281bb9716
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e4362228dd69c25c1d4ba528549fa00845a8dc24"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TestCert" and pe.signatures[i].serial=="1a:fd:14:91:d5:2f:89:ba:41:fa:6c:02:81:bb:97:16")
}
