rule FormconfA
{
	meta:
		author = "kevoreilly"
		description = "Formbook Config Extraction"
		cape_options = "clear,bp0=$c2,action0=string:rcx+1,bp1=$decoy+67,action1=string:rcx+1,count=0,typestring=Formbook Config"
		packed = "b8e44f4a0d92297c5bb5b217c121f0d032850b38749044face2b0014e789adfb"
		os = "windows"
		filetype = "executable"

	strings:
		$c2 = {44 8B C6 48 8B D3 49 8B CE E8 [4] 44 88 23 41 8B DD 48 8D [2] 66 66 66 0F 1F 84 00 00 00 00 00 BA 8D 00 00 00 41 FF C4}
		$decoy = {8B D7 0F 1F 44 00 00 0F B6 03 FF C0 48 98 48 03 D8 48 FF CA 75 ?? 44 0F B6 03 48 8D 53 01 48 8D 4C [2] E8}

	condition:
		all of them
}
