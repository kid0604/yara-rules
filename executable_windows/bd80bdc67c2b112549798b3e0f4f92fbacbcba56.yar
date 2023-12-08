rule EquationGroup_Toolset_Apr17_DiBa_Target_BH
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "7ae9a247b60dc31f424e8a7a3b3f1749ba792ff1f4ba67ac65336220021fce9f"
		os = "windows"
		filetype = "executable"

	strings:
		$op0 = { 44 89 20 e9 40 ff ff ff 8b c2 48 8b 5c 24 60 48 }
		$op1 = { 45 33 c9 49 8d 7f 2c 41 ba }
		$op2 = { 89 44 24 34 eb 17 4c 8d 44 24 28 8b 54 24 30 48 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
