rule APT_Project_Sauron_Custom_M3
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "a4736de88e9208eb81b52f29bab9e7f328b90a86512bd0baadf4c519e948e5ec"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ExampleProject.dll" fullword ascii
		$op0 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 ba }
		$op1 = { ff 15 34 20 00 10 85 c0 59 a3 60 30 00 10 75 04 }
		$op2 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 00 20 00 }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and ( all of ($s*)) and all of ($op*))
}
