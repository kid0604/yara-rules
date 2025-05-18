rule NitrogenLoaderBypass
{
	meta:
		author = "enzok"
		description = "Nitrogen Loader Exit Bypass"
		cape_options = "bp2=$exit-2,action2=jmp,count=0"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "LoadResource"
		$syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}
		$exit = {33 C9 E8 [4] E8 [4] 48 8D 84 24 [4] 48 89 44 24 ?? 4? B? E4 00 00 00 4? 8B 05 [4] B? 03 00 00 00 48 8D}

	condition:
		all of them
}
