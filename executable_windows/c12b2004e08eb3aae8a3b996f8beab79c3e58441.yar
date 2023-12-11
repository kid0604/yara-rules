import "pe"

rule INDICATOR_KB_CERT_1895de749994d0db
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "069b9cb52a325a829aba7731ead939bc4ebf3743"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2021945 Ontario Inc." and pe.signatures[i].serial=="18:95:de:74:99:94:d0:db")
}
