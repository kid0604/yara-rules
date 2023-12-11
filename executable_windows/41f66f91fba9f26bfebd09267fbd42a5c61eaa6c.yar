import "pe"

rule MALWARE_Win_Maze
{
	meta:
		author = "ditekSHen"
		description = "Detects Maze ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Uc32nbspacec97c98c99c100c101c102c103c104c105c106c107c108c109c110c" ascii
		$s1 = "\"%s\" shadowcopy delete" wide
		$s2 = "[%windir%\\system32\\wbem\\wmic" wide
		$s3 = "process call create \"cmd /c start %s\"" wide
		$s4 = "DECRYPT-FILES.html" fullword wide
		$s5 = "Dear %s, your files" wide
		$s6 = "%s! Alert! %s! Alert!" wide
		$s7 = "%BASE64_PLACEHOLDER%" fullword ascii
		$s8 = "-orDGorX0or" fullword ascii
		$s9 = { 47 45 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31
               0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 25 73
               0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 43 6f 6e 6e
               65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69
               76 65 0d 0a 0d 0a 00 50 4f 53 54 20 2f 25 73 20
               48 54 54 50 2f 31 2e 31 0d 0a 55 73 65 72 2d 41
               67 65 6e 74 3a 20 25 73 0d 0a 48 6f 73 74 3a 20
               25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65
               3a 20 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65
               6e 67 74 68 3a 20 25 64 0d 0a 43 6f 6e 6e 65 63
               74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65
               0d 0a 0d 0a 00 0d 0a 0d 0a 00 43 6f 6e 74 65 6e
               74 2d 4c 65 6e 67 74 68 3a 20 00 }

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 3 of ($s*)) or 6 of ($s*))
}
