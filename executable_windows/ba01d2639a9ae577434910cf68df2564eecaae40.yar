import "pe"

rule INDICATOR_KB_CERT_01803bc7537a1818c4ab135469963c10
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "197839b47cf975c3d6422404cbbbb5bc94f4eb46"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rare Ideas LLC" and pe.signatures[i].serial=="01:80:3b:c7:53:7a:18:18:c4:ab:13:54:69:96:3c:10")
}
