rule FormhookB
{
	meta:
		author = "kevoreilly"
		description = "Formbook Anti-hook Bypass"
		cape_options = "clear,bp0=$decode,action0=scan,bp1=$remap_ntdll,action1=setdst:ntdll,count=0,force-sleepskip=1"
		packed = "08c5f44d57f5ccc285596b3d9921bf7fbbbf7f9a827bb3285a800e4c9faf6731"
		os = "windows"
		filetype = "executable"

	strings:
		$decode = {55 8B EC 83 EC 24 53 56 57 [480-490] 00 00 5F 5E 5B 8B E5 5D C3}
		$remap_ntdll = {33 96 [2] 00 00 8D 86 [2] 00 00 68 F0 00 00 00 50 89 [2-5] E8 [4-10] 6A 00 6A 0? 8D 4D ?? 51 6A}

	condition:
		any of them
}
