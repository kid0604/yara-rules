import "pe"

rule INDICATOR_KB_CERT_61b11ef9726ab2e78132e01bd791b336
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9f7fcfd7e70dd7cd723ac20e5e7cb7aad1ba976b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Skalari" and pe.signatures[i].serial=="61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36")
}
