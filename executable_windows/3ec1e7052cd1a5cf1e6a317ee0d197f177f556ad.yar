rule PUA_VULN_Driver_Iobitinformationtechnology_Iobitunlockersys_Unlocker_F85C
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - IObitUnlocker.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "f85cca4badff17d1aa90752153ccec77a68ad282b69e3985fdc4743eaea85004"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0055006e006c006f0063006b006500720020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0049004f00620069007400200049006e0066006f0072006d006100740069006f006e00200054006500630068006e006f006c006f00670079 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0033002e0030002e00310030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0033002e0030002e00310030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0049004f0062006900740055006e006c006f0063006b00650072002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0055006e006c006f0063006b00650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0049004f0062006900740055006e006c006f0063006b00650072002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a900200049004f006200690074002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
