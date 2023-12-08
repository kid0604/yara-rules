import "pe"

rule INDICATOR_KB_CERT_97d50c7e3ab45b9a441a37d870484c10
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2e47ceb6593c9fdbd367da8b765090e48f630b33"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHENZHEN MINIWAN TECHNOLOGY CO. LTD." and pe.signatures[i].serial=="97:d5:0c:7e:3a:b4:5b:9a:44:1a:37:d8:70:48:4c:10")
}
