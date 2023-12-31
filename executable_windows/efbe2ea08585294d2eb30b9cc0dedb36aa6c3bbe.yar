rule malware_windows_moonlightmaze_custom_sniffer
{
	meta:
		description = "Rule to detect Moonlight Maze sniffer tools"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5_1 = "7b86f40e861705d59f5206c482e1f2a5"
		md5_2 = "927426b558888ad680829bd34b0ad0e7"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "/var/tmp/gogo" fullword
		$a2 = "myfilename= |%s|" fullword
		$a3 = "mypid,mygid=" fullword
		$a4 = "mypid=|%d| mygid=|%d|" fullword
		$a5 = "/var/tmp/task" fullword
		$a6 = "mydevname= |%s|" fullword

	condition:
		any of ($a*)
}
