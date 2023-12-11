import "pe"

rule INDICATOR_KB_CERT_6a568f85de2061f67ded98707d4988df
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ed7e16a65294086fbdeee09c562b0722fdb2db48"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Apladis" and pe.signatures[i].serial=="6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df")
}
