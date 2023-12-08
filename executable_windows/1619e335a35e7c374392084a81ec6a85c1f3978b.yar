import "pe"

rule INDICATOR_KB_CERT_0095e5793f2abe0b4ec9be54fd24f76ae5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "6acdfee2a1ab425b7927d0ffe6afc38c794f1240"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kommservice LLC" and pe.signatures[i].serial=="00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5")
}
