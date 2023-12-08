import "pe"

rule MAL_Emotet_BKA_Quarantine_Apr21
{
	meta:
		author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
		reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
		descripton = "The modified emotet binary replaces the original emotet on the system of the victim. The original emotet is copied to a quarantine for evidence-preservation."
		note = "The quarantine folder depends on the scope of the initial emotet infection (user or administrator). It is the temporary folder as returned by GetTempPathW under a filename starting with UDP as returned by GetTempFileNameW. To prevent accidental reinfection by a user, the quarantined emotet is encrypted using RC4 and a 0x20 bytes long key found at the start of the quarantined file (see $key)."
		sharing = "TLP:WHITE"
		date = "2021-03-23"
		description = "The modified emotet binary replaces the original emotet on the system of the victim. The original emotet is copied to a quarantine for evidence-preservation."
		os = "windows"
		filetype = "executable"

	strings:
		$key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }

	condition:
		$key at 0
}
