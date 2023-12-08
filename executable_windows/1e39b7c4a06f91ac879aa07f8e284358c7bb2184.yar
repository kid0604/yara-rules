import "pe"

rule INDICATOR_KB_CERT_00c167f04b338b1e8747b92c2197403c43
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "7af7df92fa78df96d83b3c0fd9bee884740572f9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and pe.signatures[i].serial=="00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43")
}
