rule FormhookA
{
	meta:
		author = "kevoreilly"
		description = "Formbook Anti-hook Bypass"
		cape_options = "clear,bp0=$remap_ntdll_0,action0=setedx:ntdll,count0=1,bp1=$remap_ntdll_1,action1=setdst:ntdll,count1=1,force-sleepskip=1"
		packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
		packed = "b8e44f4a0d92297c5bb5b217c121f0d032850b38749044face2b0014e789adfb"
		os = "windows"
		filetype = "executable"

	strings:
		$remap_ntdll_0 = {33 56 04 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
		$remap_ntdll_1 = {33 56 0C 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}

	condition:
		any of them
}
