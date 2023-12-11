import "pe"

rule INDICATOR_KB_CERT_00c2bb11cfc5e80bf4e8db2ed0aa7e50c5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f1044e01ff30d14a3f6c89effae9dbcd2b43658a3f7885c109f6e22af1a8da4b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rooth Media Enterprises Limited" and pe.signatures[i].serial=="00:c2:bb:11:cf:c5:e8:0b:f4:e8:db:2e:d0:aa:7e:50:c5")
}
