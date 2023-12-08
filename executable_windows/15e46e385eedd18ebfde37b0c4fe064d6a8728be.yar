private rule PotaoDll
{
	meta:
		description = "Detects potential malicious DLL files based on specific strings and names"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$dllstr1 = "?AVCncBuffer@@"
		$dllstr2 = "?AVCncRequest@@"
		$dllstr3 = "Petrozavodskaya, 11, 9"
		$dllstr4 = "_Scan@0"
		$dllstr5 = "\x00/sync/document/"
		$dllstr6 = "\\temp.temp"
		$dllname1 = "node69MainModule.dll"
		$dllname2 = "node69-main.dll"
		$dllname3 = "node69MainModuleD.dll"
		$dllname4 = "task-diskscanner.dll"
		$dllname5 = "\x00Screen.dll"
		$dllname6 = "Poker2.dll"
		$dllname7 = "PasswordStealer.dll"
		$dllname8 = "KeyLog2Runner.dll"
		$dllname9 = "GetAllSystemInfo.dll"
		$dllname10 = "FilePathStealer.dll"

	condition:
		($mz at 0) and ( any of ($dllstr*) and any of ($dllname*))
}
