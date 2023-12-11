rule PUA_VULN_Driver_Vektortsecurityservice_Vboxdrv_Antidetectpublic_CFB7
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - VBoxDrv.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "cfb7af8ac67a379e7869289aeee21837c448ea6f8ab6c93988e7aa423653bd40"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005600690072007400750061006c0042006f007800200053007500700070006f007200740020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00560065006b0074006f0072002000540031003300200053006500630075007200690074007900200053006500720076006900630065 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0034002e0030002e003100310039003200330030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0034002e0030002e003100310039003200330030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00560042006f0078004400720076 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0041006e00740069006400650074006500630074002000320030003100390020005000750062006c00690063 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00560042006f0078004400720076002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300039002d00320030003100390020004f007200610063006c006500200043006f00720070006f0072006100740069006f006e }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
