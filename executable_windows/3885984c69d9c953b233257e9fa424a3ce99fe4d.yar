rule APT_CN_TwistedPanda_SPINNER_1
{
	meta:
		author = "Check Point Research"
		description = "Detects the obfuscated variant of SPINNER payload used by TwistedPanda"
		date = "2022-04-14"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		score = 80
		hash1 = "a9fb7bb40de8508606a318866e0e5ff79b98f314e782f26c7044622939dfde81"
		os = "windows"
		filetype = "executable"

	strings:
		$config_init = { C7 ?? ?? ?? 00 00 00 C7 ?? ?? ?? 00 00 00 C6 }
		$c2_cmd_1 = { 01 00 03 10}
		$c2_cmd_2 = { 02 00 01 10}
		$c2_cmd_3 = { 01 00 01 10}
		$decryption = { 8D 83 [4] 80 B3 [5] 89 F1 6A 01 50 E8 [4] 80 B3 }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and #config_init>10 and 2 of ($c2_cmd_*) and $decryption
}
