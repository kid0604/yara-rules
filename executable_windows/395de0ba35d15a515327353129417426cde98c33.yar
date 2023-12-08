import "pe"

rule INDICATOR_KB_CERT_6cfa5050c819c4acbb8fa75979688dff
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "e7241394097402bf9e32c87cada4ba5e0d1e9923f028683713c2f339f6f59fa9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elite Web Development Ltd." and pe.signatures[i].serial=="6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff")
}
