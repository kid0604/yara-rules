rule MSSqlPass
{
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
		$s1 = "empv.exe" fullword wide
		$s2 = "Enterprise Manager PassView" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <120KB and all of them
}
