rule lateral_movement
{
	meta:
		date = "3/12/2014"
		author = "https://github.com/reed1713"
		description = "methodology sig looking for signs of lateral movement"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4688"
		$data = "PsExec.exe"
		$type1 = "Microsoft-Windows-Security-Auditing"
		$eventid1 = "4688"
		$data1 = "Windows\\System32\\net.exe"
		$type2 = "Microsoft-Windows-Security-Auditing"
		$eventid2 = "4688"
		$data2 = "Windows\\System32\\at.exe"

	condition:
		($type and $eventid and $data) or ($type1 and $eventid1 and $data1) or ($type2 and $eventid2 and $data2)
}
