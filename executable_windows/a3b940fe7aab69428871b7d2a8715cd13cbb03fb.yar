import "pe"

rule INDICATOR_KB_CERT_00b3969cd6b2f913acc99c3f61fc14852f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bd9cadcfb5cde90f493a92e43f49bf99db177724"
		hash1 = "a4d9cf67d111b79da9cb4b366400fc3ba1d5f41f71d48ca9c8bb101cb4596327"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "S.O.M GmbH" and (pe.signatures[i].serial=="b3:96:9c:d6:b2:f9:13:ac:c9:9c:3f:61:fc:14:85:2f" or pe.signatures[i].serial=="00:b3:96:9c:d6:b2:f9:13:ac:c9:9c:3f:61:fc:14:85:2f"))
}
