import "pe"

rule SUSP_AnyDesk_Compromised_Certificate_Jan24_2
{
	meta:
		description = "Detects binaries signed with a potentially compromised signing certificate of AnyDesk (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; permissive version)"
		date = "2024-02-02"
		author = "Florian Roth"
		reference = "https://download.anydesk.com/changelog.txt"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$sc1 = { 0D BF 15 2D EA F0 B9 81 A8 A9 38 D5 3F 76 9D B8 }
		$s2 = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
		$f1 = "AnyDesk Software GmbH" wide

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and all of ($s*) and not 1 of ($f*)
}
