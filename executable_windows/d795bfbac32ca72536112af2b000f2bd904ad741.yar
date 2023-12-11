rule MAL_QuasarRAT_May19_1
{
	meta:
		description = "Detects QuasarRAT malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.ensilo.com/uncovering-new-activity-by-apt10"
		date = "2019-05-27"
		modified = "2023-01-06"
		hash1 = "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Quasar.Common.Messages" ascii fullword
		$x2 = "Client.MimikatzTools" ascii fullword
		$x3 = "Resources.powerkatz_x86.dll" ascii fullword
		$x4 = "Uninstalling... good bye :-(" wide
		$xc1 = { 41 00 64 00 6D 00 69 00 6E 00 00 11 73 00 63 00
               68 00 74 00 61 00 73 00 6B 00 73 00 00 1B 2F 00
               63 00 72 00 65 00 61 00 74 00 65 00 20 00 2F 00
               74 00 6E 00 20 00 22 00 00 27 22 00 20 00 2F 00
               73 }
		$xc2 = { 00 70 00 69 00 6E 00 67 00 20 00 2D 00 6E 00 20
               00 31 00 30 00 20 00 6C 00 6F 00 63 00 61 00 6C
               00 68 00 6F 00 73 00 74 00 20 00 3E 00 20 00 6E
               00 75 00 6C 00 0D 00 0A 00 64 00 65 00 6C 00 20
               00 2F 00 61 00 20 00 2F 00 71 00 20 00 2F 00 66
               00 20 00 }

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 1 of them
}
