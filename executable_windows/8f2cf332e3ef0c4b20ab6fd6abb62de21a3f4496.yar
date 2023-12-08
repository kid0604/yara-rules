rule CN_Tools_Vscan
{
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
		$s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
		$s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
		$s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 2 of them
}
