rule APT_CN_TwistedPanda_SPINNER_2
{
	meta:
		author = "Check Point Research"
		description = "Detects an older variant of SPINNER payload used by TwistedPanda"
		date = "2022-04-14"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		score = 80
		hash1 = "28ecd1127bac08759d018787484b1bd16213809a2cc414514dc1ea87eb4c5ab8"
		os = "windows"
		filetype = "executable"

	strings:
		$config_init = { C7 [3] 00 00 00 C7 [3] 00 00 00 C6 }
		$c2_cmd_1 = { 01 00 03 10 }
		$c2_cmd_2 = { 02 00 01 10 }
		$c2_cmd_3 = { 01 00 01 10 }
		$c2_cmd_4 = { 01 00 00 10 }
		$c2_cmd_5 = { 02 00 00 10 }
		$decryption = { 80 B3 [5] 8D BB [4] 8B 56 14 8B C2 8B 4E 10 2B C1 83 F8 01 }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and #config_init>10 and 2 of ($c2_cmd_*) and $decryption
}
