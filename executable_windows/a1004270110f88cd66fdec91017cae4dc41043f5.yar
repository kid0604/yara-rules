import "pe"

rule INDICATOR_KB_CERT_0ca5acafb5fdca6f8b5d66d1339a5d85
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ab25053a3f739ddd4505cf5d9d33b5cc50f3ab35"
		hash1 = "a3ab41d9642a5a5aa6aa4fc1e316970e06fa26c6c545dd8ff56f82f41465ec08"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Valve" and pe.signatures[i].serial=="0c:a5:ac:af:b5:fd:ca:6f:8b:5d:66:d1:33:9a:5d:85")
}
