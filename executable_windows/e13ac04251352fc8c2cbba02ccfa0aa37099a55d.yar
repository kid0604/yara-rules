import "pe"

rule INDICATOR_KB_CERT_29128a56e7b3bfb230742591ac8b4718
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f9fcc798e1fccee123034fe9da9a28283de48ba7ae20f0c55ce0d36ae4625133"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Programavimo paslaugos, MB" and pe.signatures[i].serial=="29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18")
}
