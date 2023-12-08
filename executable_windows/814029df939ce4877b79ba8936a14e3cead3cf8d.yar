import "pe"

rule INDICATOR_KB_CERT_205b80a74a5dddedea6b84a1e1c44010
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1a743595dfaa29cd215ec82a6cd29bb434b709cf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Befadbffde" and pe.signatures[i].serial=="20:5b:80:a7:4a:5d:dd:ed:ea:6b:84:a1:e1:c4:40:10")
}
