import "pe"
import "hash"

rule REvil_Decryptor
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 11"
		detail = "Detects REvil's Decryptor/Sodinokibi"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = {558BEC833D4C0F410000568B7508750A837E0801}
		$op2 = {8B45088B4008A34C0F410033C0405DC3558BEC83}
		$op3 = {558BEC5153568D45FC33F650E8D51700008BD859}
		$op4 = {CCCCCCCCCCCCCCCCCCCCCCCC57565533FF33ED8B}
		$op5 = {8D8568FFFFFF50E8CE0700008D8568FFFFFF50E8}
		$x1 = {00 7B 22 61 6C 6C 22 3A 20 74 72 75 65 2C 20 22 6D 61 73 74 65 72 5F 73 6B 22 3A 20 22}
		$x2 = {22 2C 20 22 65 78 74 22 3A 20 5B}

	condition:
		uint16(0)==0x5a4d and 2 of ($op*) and all of ($x*)
}
