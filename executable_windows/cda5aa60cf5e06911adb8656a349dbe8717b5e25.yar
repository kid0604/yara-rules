rule PUA_VULN_Driver_Biostargroup_Iodriver_Biostariodriverfle_42E1
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - BS_I2cIo.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "42e170a7ab1d2c160d60abfc906872f9cfd0c2ee169ed76f6acb3f83b3eeefdb"
		hash = "f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65"
		hash = "55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0049002f004f00200049006e00740065007200660061006300650020006400720069007600650072002000660069006c0065 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00420049004f0053005400410052002000470072006f00750070 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002c00200031002c00200030002c00200030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002c00200031002c00200030002c00200030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0049002f004f0020006400720069007600650072 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00420049004f005300540041005200200049002f004f002000640072006900760065007200200066006c0065 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00420053005f0049003200630049006f002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280063002900200032003000300032002d0032003000300036002000420049004f0053005400410052002000470072006f00750070 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
