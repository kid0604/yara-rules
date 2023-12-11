import "pe"

rule INDICATOR_KB_CERT_62e745e92165213c971f5c490aea12a5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0120553d101d8cf28489570a516bd16dacda4add"
		hash = "f631405eb61bdf6f6e34657e5b99273743e1e24854942166a16f38728e19f200"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NVIDIA Corporation" and pe.signatures[i].serial=="62:e7:45:e9:21:65:21:3c:97:1f:5c:49:0a:ea:12:a5")
}
