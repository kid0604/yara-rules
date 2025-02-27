rule PUA_VULN_Driver_Adlicesoftware_Truesight_Truesight_BFC2
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - truesight.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "bfc2ef3b404294fe2fa05a8b71c7f786b58519175b7202a69fe30f45e607ff1c"
		date = "2024-08-07"
		score = 40
		id = "89e4602a-9233-5955-9edb-c09fb2b01376"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0052006f006700750065004b0069006c006c0065007200200041006e007400690072006f006f0074006b006900740020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00410064006c00690063006500200053006f006600740077006100720065 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0033002e0033002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0033002e0033002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]005400720075006500730069006700680074 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005400720075006500730069006700680074 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]005400720075006500730069006700680074 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000410064006c00690063006500200053006f00660074007700610072006500280043002900200032003000320033 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
