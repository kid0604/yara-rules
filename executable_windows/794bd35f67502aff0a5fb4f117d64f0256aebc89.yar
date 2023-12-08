import "pe"

rule INDICATOR_KB_CERT_06df5c318759d6ea9d090bfb2faf1d94
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4418e9a7aab0909fa611985804416b1aaf41e175"
		hash1 = "47dbb2594cd5eb7015ef08b7fb803cd5adc1a1fbe4849dc847c0940f1ccace35"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SpiffyTech Inc." and pe.signatures[i].serial=="06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94")
}
