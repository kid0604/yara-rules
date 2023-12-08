import "pe"

rule INDICATOR_KB_CERT_559cb90fd16e9d1ad375f050ab6a6616
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "78a149f9a04653b01df09743571df938f9873fa5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and pe.signatures[i].serial=="55:9c:b9:0f:d1:6e:9d:1a:d3:75:f0:50:ab:6a:66:16")
}
