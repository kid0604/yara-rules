import "pe"

rule INDICATOR_KB_CERT_292eb1133507f42e6f36c5549c189d5e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "48c32548ff651e2aac12716efb448f5583577e35"
		hash1 = "f0b3b36086e58964bf4b9d655568ab5c7f798bd89e7a8581069e65f8189c0b79"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Affairs-case s.r.o." and pe.signatures[i].serial=="29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e")
}
