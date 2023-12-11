rule Formhelper
{
	meta:
		author = "kevoreilly"
		description = "Formbook Config Extraction"
		cape_options = "clear,bp2=$config,action2=scan,count=0"
		packed = "0270016f451f9ba630f2ea4e2ea006fb89356627835b560bb2f4551a735ba0e1"
		os = "windows"
		filetype = "executable"

	strings:
		$config = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 [4] 48 81 EC [2] 00 00 45 33 F6 33 C0 4C 8B E9 4C 89 75}
		$decode = {66 66 66 66 0F 1F 84 00 00 00 00 00 0F B6 41 01 48 FF C9 28 41 01 49 FF C9}

	condition:
		all of them
}
