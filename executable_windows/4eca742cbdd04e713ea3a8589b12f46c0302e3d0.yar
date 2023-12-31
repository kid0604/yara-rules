rule sakula_v1_1 : RAT
{
	meta:
		description = "Sakula v1.1"
		date = "2015-10-13"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
		os = "windows"
		filetype = "executable"

	strings:
		$m1 = "%d_of_%d_for_%s_on_%s"
		$m2 = "/c ping 127.0.0.1 & del /q \"%s\""
		$m3 = "=%s&type=%d"
		$m4 = "?photoid="
		$m5 = "iexplorer"
		$m6 = "net start \"%s\""
		$v1_1 = "MicroPlayerUpdate.exe"
		$MZ = "MZ"

	condition:
		$MZ at 0 and all of them
}
