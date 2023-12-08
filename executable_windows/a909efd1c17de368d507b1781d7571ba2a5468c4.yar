rule APT_Area1_SSF_GoogleSend_Strings
{
	meta:
		description = "Detects send tool used in phishing campaign reported by Area 1 in December 2018"
		reference = "https://cdn.area1security.com/reports/Area-1-Security-PhishingDiplomacy.pdf"
		date = "2018-12-19"
		author = "Area 1 (modified by Florian Roth)"
		os = "windows"
		filetype = "executable"

	strings:
		$conf = "RefreshToken.ini" wide
		$client_id = "Enter your client ID here" wide
		$client_secret = "Enter your client secret here" wide
		$status = "We are going to send" wide
		$s1 = { b8 00 01 00 00 f0 0f b0 23 74 94 f3 90 80 3d ?? ?? ?? ?? 00 75 ??
         51 52 6a 00 e8 ?? ?? ?? ?? 5a 59 b8 00 01 00 00 f0 0f b0
         23 0f ?? ?? ?? ?? ?? 51 52 6a 0a e8 ?? ?? ?? ?? 5a 59 eb c3 }

	condition:
		uint16(0)==0x5a4d and 3 of them
}
