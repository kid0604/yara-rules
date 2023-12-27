import "pe"
import "hash"

rule Ransom_Sodinokibi_Kaseya_supply_chain_attack
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 7"
		os = "windows"
		filetype = "executable"

	strings:
		$header = {4D 5A 90 00 03 00 00 00 04 00 00 00 
                 FF FF 00 00 B8 00 00 00 00 00 00 00 
                 40 00 00 00 00 00 00 00 00 00 00 00 
                 00 00 00 00 00 00 00 00 00 00 00 00 
                 00 00 00 00 00 00 00 00 00 00 00 00 
                 ?? ?? 00 00 0E 1F BA 0E 00 B4 09 CD 
                 21 B8 01 4C CD 21 54 68 69 73 20 70 
                 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 
                 74 20 62 65 20 72 75 6E 20 69 6E 20 
                 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 
                 24 00 00 00 00 00 00 00}
		$s1 = {64 68 4B 65 79 41 67 72 65 65 6D 65 6E 74 00 00 63 72 79 70 74 6F 70 72 6F 00 00 00 44 45 53 2D 45 43 42 00 63 72 79 70 74 6F 63 6F 6D 00 00 00 64 65 73 2D 65 63 62 00 69 64 2D 47 6F 73 74 52 33 34 31 31 2D 39 34 2D 77 69 74 68 2D 47 6F 73 74 52 33 34 31 30 2D 32 30 30 31 00 44 45 53 2D 43 46 42 00 47 4F 53 54 20 52 20 33 34 2E 31 31 2D 39 34 20 77 69 74 68 20 47 4F 53 54 20 52 20 33 34 2E 31 30 2D 32 30 30 31 00 00 64 65 73 2D 63 66 62}
		$s2 = {00 43 72 79 70 74 41 63 71 75 69 72 65 43 6F 6E 74 65 78 74 57 00 00 00 00 43 72 79 70 74 47 65 6E 52 61 6E 64 6F 6D 00 00 43 72 79 70 74 52 65 6C 65 61 73 65 43 6F 6E 74 65 78 74 00}
		$s3 = "MpSvc.dll" fullword ascii
		$s4 = {1F 42 72 6F 75 69 6C 6C 65 74 74 65 62 75 73 69 6E 65 73 73 40 6F 75 74 6C 6F 6F 6B 2E 63 6F 6D 30}

	condition:
		uint16(0)==0x5a4d and $header at 0 and 3 of ($s*)
}