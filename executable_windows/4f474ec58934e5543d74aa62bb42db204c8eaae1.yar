import "pe"

rule INDICATOR_KB_CERT_02e44d7d1d38ae223b27a02bacd79b53
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "34e0ecae125302d5b1c4a7412dbf17bdc1b59f04"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and pe.signatures[i].serial=="02:e4:4d:7d:1d:38:ae:22:3b:27:a0:2b:ac:d7:9b:53")
}
