rule PUA_VULN_Driver_Interfacecorporation_Cpxcsys_Gpcxcdiobmpcicpci_05C1
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - CP2X72C.SYS"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "05c15a75d183301382a082f6d76bf3ab4c520bf158abca4433d9881134461686"
		hash = "4b4ea21da21a1167c00b903c05a4e3af6c514ea3dfe0b5f371f6a06305e1d27f"
		date = "2024-08-07"
		score = 40
		id = "da7c0052-5ff9-5257-a65f-7856f772b4c6"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004700500043002d0032005800370032004300200049002f004f0020004d006f00640075006c006500200044006500760069006300650020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0049006e007400650072006600610063006500200043006f00720070006f0072006100740069006f006e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0033002e00330030002e00330033002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0033002e00330030002e00330033002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0043005000320058003700320043002e005300590053 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004700500043002d00320058003700320043002000440049004f002d0042004d0028005000430049002f0043002d0050004300490029 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0043005000320058003700320043002e005300590053 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400200032003000300031002c0020003200300032003000200049006e007400650072006600610063006500200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
