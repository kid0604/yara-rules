rule Bumblebee
{
	meta:
		author = "enzo & kevoreilly"
		description = "BumbleBee Anti-VM Bypass"
		cape_options = "bp0=$antivm1+2,bp1=$antivm2+2,bp1=$antivm3+38,action0=jmp,action1=skip,count=0,force-sleepskip=1"
		os = "windows"
		filetype = "executable"

	strings:
		$antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
		$antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
		$antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15 [4] E8 [4] 84 c0}

	condition:
		uint16(0)==0x5A4D and any of them
}
