rule APT_CN_TwistedPanda_64bit_Loader
{
	meta:
		author = "Check Point Research"
		description = "Detects the 64bit Loader DLL used by TwistedPanda"
		date = "2022-04-14"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		score = 80
		hash1 = "e0d4ef7190ff50e6ad2a2403c87cc37254498e8cc5a3b2b8798983b1b3cdc94f"
		os = "windows"
		filetype = "executable"

	strings:
		$path_check = { 48 8D [6] 48 8B ?? 48 81 [5] 72 }
		$shellcode_read = { 48 8B D0 41 B8 F0 16 00 00 48 8B CF 48 8B D8 FF}
		$shellcode_allocate = { BA F0 16 00 00 44 8D 4E 40 33 C9 41 B8 00 30 00 00 FF }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and $path_check and $shellcode_allocate and $shellcode_read
}
