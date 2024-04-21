import "pe"

rule PUA_AnyDesk_Compromised_Certificate_Revoked_Jan24
{
	meta:
		description = "Detects binaries signed with a compromised signing certificate of AnyDesk (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8) after it was revoked. This is not a threat detection. It detects an outdated version of AnyDesk that was signed with a certificate that has been revoked."
		date = "2024-02-05"
		author = "Florian Roth"
		reference = "https://anydesk.com/en/public-statement"
		score = 50
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and pe.signatures[i].serial=="0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8")
}
