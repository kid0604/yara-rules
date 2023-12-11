import "pe"

rule INDICATOR_KB_CERT_0788260f8541539d97f49ddaa837b166
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "569511fdc5e8dea454e97b005de1af5272d4bd32"
		hash1 = "6ad407d5c7e4574c7452a1a27da532ee9a55bb4074e43aa677703923909169e4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TechSmith Corporation" and pe.signatures[i].serial=="07:88:26:0f:85:41:53:9d:97:f4:9d:da:a8:37:b1:66")
}
