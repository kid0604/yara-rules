rule FormconfB
{
	meta:
		author = "kevoreilly"
		description = "Formbook Config Extraction"
		cape_options = "clear,bp0=$c2,action0=string:rcx+1,bp1=$decoy,action1=string:rcx+1,bp2=$config,action2=scan,count=0,typestring=Formbook Config"
		packed = "60571b2683e7b753a77029ebe9b5e1cb9f3fbfa8d6a43e4b7239eefd13141ae4"
		os = "windows"
		filetype = "executable"

	strings:
		$c2 = {44 0F B6 5D ?? 45 84 DB 74 ?? 48 8D 4D [1-5] 41 80 FB 2F 74 11 0F B6 41 01 48 FF C1 FF C3 44 0F B6 D8 84 C0 75}
		$decoy = {45 3B B5 [2] 00 00 [0-7] 44 8D 1C 33 48 8D 7D [1-5] 42 C6 44 [2] 00 [0-4] 48 8B CF E8}
		$config = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 [4] 48 81 EC [2] 00 00 45 33 F6 33 C0 4C 8B E9 4C 89 75}

	condition:
		2 of them
}
