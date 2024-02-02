import "pe"

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_3
{
	meta:
		description = "Detects binaries signed with a potentially compromised signing certificate of AnyDesk after it was revoked (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; version that uses dates for validation)"
		date = "2024-02-02"
		author = "Florian Roth"
		reference = "https://download.anydesk.com/changelog.txt"
		score = 75
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and pe.signatures[i].serial=="0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8" and (pe.signatures[i].not_before>1706486400 or pe.timestamp>1706486400))
}
