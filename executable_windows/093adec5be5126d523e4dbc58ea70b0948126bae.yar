import "pe"

rule INDICATOR_KB_CERT_00b649a966410f62999c939384af553919
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a0c6cd25e1990c0d03b6ec1ad5a140f2c8014a8c2f1f4f227ee2597df91a8b6c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F.A.T. SARL" and pe.signatures[i].serial=="00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19")
}
