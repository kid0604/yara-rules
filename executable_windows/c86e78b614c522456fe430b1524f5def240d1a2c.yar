rule FE_CPE_MS17_010_RANSOMWARE
{
	meta:
		version = "1.1"
		author = "Ian.Ahl@fireeye.com @TekDefense, Nicholas.Carr@mandiant.com @ItsReallyNick"
		date = "2017-06-27"
		description = "Probable PETYA ransomware using ETERNALBLUE, WMIC, PsExec"
		reference = "https://www.fireeye.com/blog/threat-research/2017/06/petya-ransomware-spreading-via-eternalblue-exploit.html"
		os = "windows"
		filetype = "executable"

	strings:
		$dmap01 = "\\\\.\\PhysicalDrive" nocase ascii wide
		$dmap02 = "\\\\.\\PhysicalDrive0" nocase ascii wide
		$dmap03 = "\\\\.\\C:" nocase ascii wide
		$dmap04 = "TERMSRV" nocase ascii wide
		$dmap05 = "\\admin$" nocase ascii wide
		$dmap06 = "GetLogicalDrives" nocase ascii wide
		$dmap07 = "GetDriveTypeW" nocase ascii wide
		$msg01 = "WARNING: DO NOT TURN OFF YOUR PC!" nocase ascii wide
		$msg02 = "IF YOU ABORT THIS PROCESS" nocase ascii wide
		$msg03 = "DESTROY ALL OF YOUR DATA!" nocase ascii wide
		$msg04 = "PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED" nocase ascii wide
		$msg05 = "your important files are encrypted" ascii wide
		$msg06 = "Your personal installation key" nocase ascii wide
		$msg07 = "worth of Bitcoin to following address" nocase ascii wide
		$msg08 = "CHKDSK is repairing sector" nocase ascii wide
		$msg09 = "Repairing file system on " nocase ascii wide
		$msg10 = "Bitcoin wallet ID" nocase ascii wide
		$msg11 = "wowsmith123456@posteo.net" nocase ascii wide
		$msg12 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" nocase ascii wide
		$msg_pcre = /(en|de)crypt(ion|ed\.)/
		$functions01 = "need dictionary" nocase ascii wide
		$functions02 = "comspec" nocase ascii wide
		$functions03 = "OpenProcessToken" nocase ascii wide
		$functions04 = "CloseHandle" nocase ascii wide
		$functions05 = "EnterCriticalSection" nocase ascii wide
		$functions06 = "ExitProcess" nocase ascii wide
		$functions07 = "GetCurrentProcess" nocase ascii wide
		$functions08 = "GetProcAddress" nocase ascii wide
		$functions09 = "LeaveCriticalSection" nocase ascii wide
		$functions10 = "MultiByteToWideChar" nocase ascii wide
		$functions11 = "WideCharToMultiByte" nocase ascii wide
		$functions12 = "WriteFile" nocase ascii wide
		$functions13 = "CoTaskMemFree" nocase ascii wide
		$functions14 = "NamedPipe" nocase ascii wide
		$functions15 = "Sleep" nocase ascii wide
		$cmd01 = "wevtutil cl Setup" ascii wide nocase
		$cmd02 = "wevtutil cl System" ascii wide nocase
		$cmd03 = "wevtutil cl Security" ascii wide nocase
		$cmd04 = "wevtutil cl Application" ascii wide nocase
		$cmd05 = "fsutil usn deletejournal" ascii wide nocase
		$cmd06 = "schtasks " nocase ascii wide
		$cmd07 = "/Create /SC " nocase ascii wide
		$cmd08 = " /TN " nocase ascii wide
		$cmd09 = "at %02d:%02d %ws" nocase ascii wide
		$cmd10 = "shutdown.exe /r /f" nocase ascii wide
		$cmd11 = "-accepteula -s" nocase ascii wide
		$cmd12 = "wmic"
		$cmd13 = "/node:" nocase ascii wide
		$cmd14 = "process call create" nocase ascii wide

	condition:
		3 of ($dmap*) and 2 of ($msg*) and 9 of ($functions*) and 7 of ($cmd*)
}
