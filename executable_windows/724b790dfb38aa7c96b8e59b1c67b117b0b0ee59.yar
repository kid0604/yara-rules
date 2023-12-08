import "pe"

rule INDICATOR_KB_CERT_6e3b09f43c3a0fd53b7d600f08fae2b5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "677054afcbfecb313f93f27ed159055dc1559ad0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Divisible Limited" and pe.signatures[i].serial=="6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5")
}
