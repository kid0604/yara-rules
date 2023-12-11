import "pe"

rule INDICATOR_KB_CERT_5dd1cb148a90123dcc13498b54e5a798
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3a7c692345b67c7a2b21a6d94518588c8bbe514c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "33adab6a2ixdac07i4cLb4ac05j6yG2ew95e" and pe.signatures[i].serial=="5d:d1:cb:14:8a:90:12:3d:cc:13:49:8b:54:e5:a7:98")
}
