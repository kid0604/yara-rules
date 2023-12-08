import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients
{
	meta:
		description = "Detects executables referencing many file transfer clients. Observed in information stealers"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "FileZilla\\recentservers.xml" ascii wide
		$s2 = "Ipswitch\\WS_FTP\\" ascii wide
		$s3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
		$s4 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" ascii wide
		$s5 = "CoreFTP\\sites" ascii wide
		$s6 = "FTPWare\\COREFTP\\Sites" ascii wide
		$s7 = "HKEY_CURRENT_USERSoftwareFTPWareCOREFTPSites" ascii wide
		$s8 = "FTP Navigator\\Ftplist.txt" ascii wide
		$s9 = "FlashFXP\\3quick.dat" ascii wide
		$s10 = "SmartFTP\\" ascii wide
		$s11 = "cftp\\Ftplist.txt" ascii wide
		$s12 = "Software\\DownloadManager\\Passwords\\" ascii wide
		$s13 = "jDownloader\\config\\database.script" ascii wide
		$s14 = "FileZilla\\sitemanager.xml" ascii wide
		$s15 = "Far Manager\\Profile\\PluginsData\\" ascii wide
		$s16 = "FTPGetter\\Profile\\servers.xml" ascii wide
		$s17 = "FTPGetter\\servers.xml" ascii wide
		$s18 = "Estsoft\\ALFTP\\" ascii wide
		$s19 = "Far\\Plugins\\FTP\\" ascii wide
		$s20 = "Far2\\Plugins\\FTP\\" ascii wide
		$s21 = "Ghisler\\Total Commander" ascii wide
		$s22 = "LinasFTP\\Site Manager" ascii wide
		$s23 = "CuteFTP\\sm.dat" ascii wide
		$s24 = "FlashFXP\\4\\Sites.dat" ascii wide
		$s25 = "FlashFXP\\3\\Sites.dat" ascii wide
		$s26 = "VanDyke\\Config\\Sessions\\" ascii wide
		$s27 = "FTP Explorer\\" ascii wide
		$s28 = "TurboFTP\\" ascii wide
		$s29 = "FTPRush\\" ascii wide
		$s30 = "LeapWare\\LeapFTP\\" ascii wide
		$s31 = "FTPGetter\\" ascii wide
		$s32 = "Far\\SavedDialogHistory\\" ascii wide
		$s33 = "Far2\\SavedDialogHistory\\" ascii wide
		$s34 = "GlobalSCAPE\\CuteFTP " ascii wide
		$s35 = "Ghisler\\Windows Commander" ascii wide
		$s36 = "BPFTP\\Bullet Proof FTP\\" ascii wide
		$s37 = "Sota\\FFFTP" ascii wide
		$s38 = "FTPClient\\Sites" ascii wide
		$s39 = "SOFTWARE\\Robo-FTP 3.7\\" ascii wide
		$s40 = "MAS-Soft\\FTPInfo\\" ascii wide
		$s41 = "SoftX.org\\FTPClient\\Sites" ascii wide
		$s42 = "BulletProof Software\\BulletProof FTP Client\\" ascii wide
		$s43 = "BitKinex\\bitkinex.ds" ascii wide
		$s44 = "Frigate3\\FtpSite.XML" ascii wide
		$s45 = "Directory Opus\\ConfigFiles" ascii wide
		$s56 = "SoftX.org\\FTPClient\\Sites" ascii wide
		$s57 = "South River Technologies\\WebDrive\\Connections" ascii wide

	condition:
		uint16(0)==0x5a4d and 6 of them
}
