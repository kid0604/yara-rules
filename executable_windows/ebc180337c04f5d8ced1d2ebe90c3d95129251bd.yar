import "pe"

rule INDICATOR_KB_CERT_00e41537b8dd65670d6eb01954becacf1e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "150ff604efa1e4868ea47c5d48244e57fa4b9196"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marketing Concept s.r.o." and (pe.signatures[i].serial=="e4:15:37:b8:dd:65:67:0d:6e:b0:19:54:be:ca:cf:1e" or pe.signatures[i].serial=="00:e4:15:37:b8:dd:65:67:0d:6e:b0:19:54:be:ca:cf:1e"))
}
