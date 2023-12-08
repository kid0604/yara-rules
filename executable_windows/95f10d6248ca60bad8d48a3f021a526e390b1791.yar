import "pe"

rule INDICATOR_KB_CERT_4c450eccd61d334e0afb2b2d9bb1d812
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "4c450eccd61d334e0afb2b2d9bb1d812"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ANJELA KEY LIMITED" and pe.signatures[i].serial=="4c:45:0e:cc:d6:1d:33:4e:0a:fb:2b:2d:9b:b1:d8:12")
}
