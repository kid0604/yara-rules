import "pe"

rule INDICATOR_KB_CERT_17ccecc181ed65a357edf3b01df62cc9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b64bd77a58c90f76afd6c4ce0b38c54c3c6088b818d0b83e5435d89e3dc01cda"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="17:cc:ec:c1:81:ed:65:a3:57:ed:f3:b0:1d:f6:2c:c9")
}
