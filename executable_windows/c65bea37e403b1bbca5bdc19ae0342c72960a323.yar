import "pe"

rule INDICATOR_KB_CERT_98a04ea05e8a949a4d880d0136794df3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0387ce856978cfa3e161fc03751820f003b478f3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FRVFMPRLNIMAMSUIMT" and pe.signatures[i].serial=="98:a0:4e:a0:5e:8a:94:9a:4d:88:0d:01:36:79:4d:f3")
}
