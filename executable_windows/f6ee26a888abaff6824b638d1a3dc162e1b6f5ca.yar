import "pe"

rule INDICATOR_KB_CERT_0bc9b800f480691bd6b60963466b0c75
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8b6c4fc3d54f41ac137795e64477491c93bdf7f1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HasCred ApS" and pe.signatures[i].serial=="0b:c9:b8:00:f4:80:69:1b:d6:b6:09:63:46:6b:0c:75")
}
