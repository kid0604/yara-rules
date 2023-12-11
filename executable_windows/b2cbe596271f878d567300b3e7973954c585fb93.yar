import "pe"

rule INDICATOR_KB_CERT_08d4352185317271c1cec9d05c279af7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "52fe4ecd6c925e89068fee38f1b9a669a70f8bab"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Retalit LLC" and pe.signatures[i].serial=="08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7")
}
