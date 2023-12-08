import "pe"

rule INDICATOR_KB_CERT_330000026551ae1bbd005cbfbd000000000265
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e168609353f30ff2373157b4eb8cd519d07a2bff"
		hash1 = "a471fdf6b137a6035b2a2746703cd696089940698fd533860d34e71cc6586850"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Windows" and pe.signatures[i].issuer contains "Microsoft Windows Production PCA 2011" and pe.signatures[i].serial=="33:00:00:02:65:51:ae:1b:bd:00:5c:bf:bd:00:00:00:00:02:65" and 1614796238<=pe.signatures[i].not_after)
}
