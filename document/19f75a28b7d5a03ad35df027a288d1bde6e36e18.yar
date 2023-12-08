rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_1
{
	meta:
		description = "Detects suspicious OneNote attachment that embeds suspicious payload, e.g. an executable (FPs possible if the PE is attached separately)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2023-01-27"
		score = 65
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$ge1 = "5xbjvWUmEUWkxI1NC3qer"
		$ge2 = "cW471lJhFFpMSNTQt6nq"
		$ge3 = "nFuO9ZSYRRaTEjU0Lep6s"
		$sp1 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG"
		$sp2 = "RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl"
		$sp3 = "UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ"
		$sp4 = "VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVy"
		$sp5 = "RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlc"
		$sp6 = "UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZX"
		$se1 = "QGVjaG8gb2Zm"
		$se2 = "BlY2hvIG9mZ"
		$se3 = "AZWNobyBvZm"
		$se4 = "PEhUQTpBUFBMSUNBVElPTi"
		$se5 = "xIVEE6QVBQTElDQVRJT04g"
		$se6 = "8SFRBOkFQUExJQ0FUSU9OI"
		$se7 = "TAAAAAEUAg"
		$se8 = "wAAAABFAIA"
		$se9 = "MAAAAARQCA"

	condition:
		filesize <5MB and 1 of ($ge*) and 1 of ($s*)
}
