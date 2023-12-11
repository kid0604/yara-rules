import "pe"

rule INDICATOR_KB_CERT_fd8c468cc1b45c9cfb41cbd8c835cc9e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "08fc56a14dcdc9e67b9a890b65064b8279176057"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and pe.signatures[i].serial=="fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e")
}
