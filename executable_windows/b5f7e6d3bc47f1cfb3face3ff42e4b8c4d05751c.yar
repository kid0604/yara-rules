rule APT_CN_TwistedPanda_loader
{
	meta:
		author = "Check Point Research"
		description = "Detects loader used by TwistedPanda"
		date = "2022-04-14"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		score = 80
		hash1 = "5b558c5fcbed8544cb100bd3db3c04a70dca02eec6fedffd5e3dcecb0b04fba0"
		hash2 = "efa754450f199caae204ca387976e197d95cdc7e83641444c1a5a91b58ba6198"
		os = "windows"
		filetype = "executable"

	strings:
		$seq1 = { 6A 40 68 00 30 00 00 }
		$seq2 = { 6A 00 50 6A 14 8D ?? ?? ?? ?? ?? 50 53 FF }
		$seq3 = { 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 80 }
		$decryption = { 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and all of ($seq*) and $decryption
}
