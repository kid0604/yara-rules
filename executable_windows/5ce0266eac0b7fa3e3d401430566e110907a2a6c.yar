import "pe"

rule INDICATOR_KB_CERT_2ba40f65086686dd4ab7171e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "842f81869c2f4f2ba2a7e6513501166e2679108a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RITEIL SISTEMS LLC" and pe.signatures[i].serial=="2b:a4:0f:65:08:66:86:dd:4a:b7:17:1e")
}
