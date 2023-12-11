import "pe"

rule INDICATOR_KB_CERT_7e0ccda0ef37acef6c2ebe4538627e5c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "a758d6799e218dd66261dc5e2e21791cbcccd6cb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Orangetree B.V." and pe.signatures[i].serial=="7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c")
}
