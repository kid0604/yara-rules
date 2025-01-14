rule NitrogenLoaderAES
{
	meta:
		author = "enzok"
		description = "NitrogenLoader AES and IV"
		cape_options = "bp0=$keyiv0+8,action0=dump:ecx::64,hc0=1,bp1=$keyiv0*-4,action1=dump:ecx::32,hc1=1,count=0"
		os = "windows"
		filetype = "executable"

	strings:
		$keyiv0 = {48 8B 8C 24 [4] E8 [3] 00 4? 89 84 24 [4] 4? 8B 84 24 [4] 4? 89 84 24 [4] 4? 8B 8C 24 [4] E8 [3] 00}
		$keyiv1 = {48 89 84 24 [4] 4? 8B 84 24 [4] 4? 8B 94 24 [4] 4? 8D 8C 24 [4] E8 [3] FF}
		$keyiv2 = {48 63 84 24 [4] 4? 8B C0 4? 8B 94 24 [4] 4? 8D 8C 24 [4] E8 [3] FF 4? 8B 84 24}

	condition:
		all of them
}
