rule EditServer_HackTool
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii
		$x1 = "WinEggDrop Shell Congirator" fullword ascii

	condition:
		5 of ($s*) or $x1
}
