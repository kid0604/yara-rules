rule Enigma_Protected_Malware_alt_1
{
	meta:
		description = "Detects samples packed by Enigma Protector"
		author = "Florian Roth (Nextron Systems) with the help of binar.ly"
		reference = "https://goo.gl/OEVQ9w"
		date = "2017-02-03"
		hash1 = "d4616f9706403a0d5a2f9a8726230a4693e4c95c58df5c753ccc684f1d3542e2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 5d 5d 5d aa bf 5e 95 d6 dc 51 5d 5d 5d 5e 98 0d }
		$s2 = { 52 d9 47 5d 5d 5d dd a6 b4 52 d9 4c 5d 5d 5d 3b }
		$s3 = { 9f 59 14 52 d8 a9 a2 a2 a2 00 9f 51 5d d6 d1 79 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
