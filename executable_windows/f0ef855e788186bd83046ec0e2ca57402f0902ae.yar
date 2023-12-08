import "pe"

rule INDICATOR_KB_CERT_04c7cdcc1698e25b493eb4338d5e2f8b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "60974f5cc654e6f6c0a7332a9733e42f19186fbb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3AN LIMITED" and pe.signatures[i].serial=="04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b")
}
