import "pe"

rule INDICATOR_KB_CERT_a1a3e7280e0a2df12f84309649820519
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "33d254c711937b469d1b08ef15b0a9f5b4d27250"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nir Sofer" and pe.signatures[i].serial=="a1:a3:e7:28:0e:0a:2d:f1:2f:84:30:96:49:82:05:19")
}
