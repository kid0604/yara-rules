import "pe"

rule INDICATOR_KB_CERT_00ac0a7b9420b369af3ddb748385b981
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "15b56f8b0b22dbc7c08c00d47ee06b04fa7df5fe"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Tochka" and pe.signatures[i].serial=="00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81")
}
