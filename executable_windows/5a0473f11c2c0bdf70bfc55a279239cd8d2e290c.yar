import "pe"

rule INDICATOR_KB_CERT_59e378994cf1c0022764896d826e6bb8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "9a17d31e9191644945e920bc1e7e08fbd00b62f4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SEVA MEDICAL LTD" and pe.signatures[i].serial=="59:e3:78:99:4c:f1:c0:02:27:64:89:6d:82:6e:6b:b8")
}
