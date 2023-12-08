import "pe"

rule MAL_Shellcode_Loader_Apr23
{
	meta:
		author = "X__Junior (Nextron Systems)"
		reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
		description = "Detects Shellcode loader as seen being used by Gopuram backdoor"
		date = "2023-04-03"
		hash1 = "6ce5b6b4cdd6290d396465a1624d489c7afd2259a4d69b73c6b0ba0e5ad4e4ad"
		hash2 = "b56279136d816a11cf4db9fc1b249da04b3fa3aef4ba709b20cdfbe572394812"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 41 C1 CB 0D 0F BE 03 48 FF C3 44 03 D8 80 7B ?? 00 75 ?? 41 8D 04 13 3B C6 74 }
		$op2 = { B9 49 F7 02 78 4C 8B E8 E8 ?? ?? ?? ?? B9 58 A4 53 E5 48 89 44 24 ?? E8 ?? ?? ?? ?? B9 10 E1 8A C3 48 8B F0 E8 ?? ?? ?? ?? B9 AF B1 5C 94 48 89 44 24 ?? E8 }

	condition:
		all of them
}
