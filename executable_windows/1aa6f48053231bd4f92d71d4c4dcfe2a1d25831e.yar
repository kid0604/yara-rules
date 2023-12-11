import "pe"

rule INDICATOR_KB_CERT_00aff762e907f0644e76ed8a7485fb12a1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7b0c55ae9f8f5d82edbc3741ea633ae272bbb2207da8e88694e06d966d86bc63"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lets Start SP Z O O" and pe.signatures[i].serial=="00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1")
}
