rule StuxNet_Malware_1
{
	meta:
		description = "Stuxnet Sample - file malware.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		$op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		$op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

	condition:
		all of them
}
