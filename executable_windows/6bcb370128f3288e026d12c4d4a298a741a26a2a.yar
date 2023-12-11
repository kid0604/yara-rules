import "pe"

rule INDICATOR_KB_CERT_00f4d2def53bccb0dd2b7d54e4853a2fc5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d5431403ba7b026666e72c675aac6c46720583a60320c5c2c0f74331fe845c35"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PETROYL GROUP, TOV" and pe.signatures[i].serial=="00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5")
}
