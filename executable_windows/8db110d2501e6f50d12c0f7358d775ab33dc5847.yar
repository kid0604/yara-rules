import "pe"

rule INDICATOR_KB_CERT_e9268ed63a7d7e9dfd40a664ddfbaf18
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0767b9ab857b8e24282b80a7368323689a842e6c8b5a00a4f965c03e375e8b0d"
		reason = "Hive"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Casta, s.r.o." and pe.signatures[i].serial=="e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18")
}
