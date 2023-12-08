rule FormconfC
{
	meta:
		author = "kevoreilly"
		description = "Formbook Config Extraction"
		cape_options = "clear,bp0=$c2,hc0=1,action0=string:rcx+1,bp1=$decoy,action1=string:rcx+1,count=0,typestring=Formbook Config"
		packed = "0270016f451f9ba630f2ea4e2ea006fb89356627835b560bb2f4551a735ba0e1"
		os = "windows"
		filetype = "executable"

	strings:
		$c2 = {49 8D 95 [2] 00 00 49 8D 8D [2] 00 00 41 B8 07 00 00 00 E8 [4] 49 8B CD 45 88 B5 [2] 00 00 E8 [4] 33 C0}
		$decoy = {45 3B B5 [2] 00 00 [0-7] 44 8D 1C 33 48 8D 7D [1-5] 42 C6 44 [2] 00 [0-4] 48 8B CF E8}

	condition:
		all of them
}
