rule FormhookB_alt_2
{
	meta:
		author = "kevoreilly"
		description = "Formbook Anti-hook Bypass"
		cape_options = "clear,bp0=$decode,action0=scan,hc0=1,bp1=$remap_ntdll+6,action1=setdst:ntdll,count=0,force-sleepskip=1"
		packed = "08c5f44d57f5ccc285596b3d9921bf7fbbbf7f9a827bb3285a800e4c9faf6731"
		os = "windows"
		filetype = "executable"

	strings:
		$decode = {55 8B EC 83 EC 24 53 56 57 [480-520] 8B E5 5D C3}
		$remap_ntdll = {90 90 90 90 90 90 8B (86 [2] 00 00|46 ??|06) 5F 5E 5B 8B E5 5D C3}

	condition:
		any of them
}
