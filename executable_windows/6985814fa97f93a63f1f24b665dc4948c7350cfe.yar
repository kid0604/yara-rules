import "pe"

rule DarkComet_5
{
	meta:
		maltype = "DarkComet RAT"
		author = "https://github.com/reed1713"
		description = "Malware creates the MSDCSC directory, which is a common path utilized by DarkComet, as well as the mutex pattern."
		os = "windows"
		filetype = "executable"

	strings:
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4688"
		$data = /AppData\\Local\\Temp\\MSDCSC\\.+\.exe/
		$type1 = "Microsoft-Windows-Security-Auditing"
		$eventid1 = "4674"
		$data1 = /DC_MUTEX-[0-9A-Z]{7}/

	condition:
		($type and $eventid and $data) or ($type1 and $eventid1 and $data1)
}
