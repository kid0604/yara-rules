import "pe"

rule INDICATOR_KB_CERT_04f131322cc31d92c849fca351d2f141
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1e6706b746a7409f4e9a39855c5dde4155a13056"
		hash1 = "a19177caff09dfa62c5a5598221cefd7e8871e81bda0cdc9f09c98180360a1e3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Discord Inc." and pe.signatures[i].serial=="04:f1:31:32:2c:c3:1d:92:c8:49:fc:a3:51:d2:f1:41")
}
