import "pe"

rule INDICATOR_KB_CERT_02aa497d39320fc979ad96160d90d410
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "33e8e72a75d6f424c5a10d2b771254c07a7d9c138e5fea703117fe60951427ae"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MATCHLESS GIFTS, INC." and pe.signatures[i].serial=="02:aa:49:7d:39:32:0f:c9:79:ad:96:16:0d:90:d4:10")
}
