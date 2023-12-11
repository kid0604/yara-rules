rule PUA_VULN_Driver_Pinduoduoltdcorp_Vboxdrv_Pinduoduosecurevdi_9DAB
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - VBoxDrv.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "9dab4b6fddc8e1ec0a186aa8382b184a5d52cfcabaaf04ff9e3767021eb09cf4"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005600690072007400750061006c0042006f007800200053007500700070006f007200740020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00500069006e00640075006f00640075006f0020004c0074006400200043006f00720070 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0032002e0030002e003100330037003900300034 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0032002e0030002e003100330037003900300034 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00560042006f0078004400720076 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00500069006e00640075006f00640075006f00200053006500630075007200650020005600440049 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00560042006f0078004400720076002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000310035002d0032003000320031002000500069006e00640075006f00640075006f00200043006f00720070006f0072006100740069006f006e }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
