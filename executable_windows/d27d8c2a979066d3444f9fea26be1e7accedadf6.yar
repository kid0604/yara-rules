import "pe"

rule INDICATOR_KB_CERT_beb721fcb3274c984479d6554efe8f49
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2d1fd0cce4aa7e7dc6dd114a301825a7b8e887cf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CONFUSER" and pe.signatures[i].serial=="be:b7:21:fc:b3:27:4c:98:44:79:d6:55:4e:fe:8f:49")
}
