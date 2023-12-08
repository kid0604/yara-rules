import "pe"

rule INDICATOR_KB_CERT_2e4a279bde2eb688e8ab30f5904fa875
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0cdf4e992af760e59f3ea2f1648804d2a2b47bbc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lespeed Technology Co., Ltd" and pe.signatures[i].serial=="2e:4a:27:9b:de:2e:b6:88:e8:ab:30:f5:90:4f:a8:75")
}
