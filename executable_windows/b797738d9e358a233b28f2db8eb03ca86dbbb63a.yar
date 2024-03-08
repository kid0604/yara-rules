rule Pikahook
{
	meta:
		author = "kevoreilly"
		description = "Pikabot anti-hook bypass"
		cape_options = "clear,sysbp=$indirect+40,sysbpmode=1,force-sleepskip=1"
		packed = "89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9"
		os = "windows"
		filetype = "executable"

	strings:
		$indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1 [4] FF 15}
		$sysenter1 = {89 44 24 08 8D 85 20 FC FF FF C7 44 24 04 FF FF 1F 00 89 04 24 E8}
		$sysenter2 = {C7 44 24 0C 00 00 00 02 C7 44 24 08 00 00 00 02 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8}

	condition:
		uint16(0)==0x5A4D and 2 of them
}
