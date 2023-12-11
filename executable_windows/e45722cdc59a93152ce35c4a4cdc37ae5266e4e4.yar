rule RedLine_b
{
	meta:
		id = "6Ds02SHJ9xqDC5ehVb5PEZ"
		fingerprint = "5ecb15004061205cdea7bcbb6f28455b6801d82395506fd43769d591476c539e"
		version = "1.0"
		creation_date = "2021-10-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies RedLine stealer."
		category = "MALWARE"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "Account" ascii wide
		$ = "AllWallets" ascii wide
		$ = "Autofill" ascii wide
		$ = "Browser" ascii wide
		$ = "BrowserVersion" ascii wide
		$ = "Chr_0_M_e" ascii wide
		$ = "CommandLineUpdate" ascii wide
		$ = "ConfigReader" ascii wide
		$ = "DesktopMessanger" ascii wide
		$ = "Discord" ascii wide
		$ = "DownloadAndExecuteUpdate" ascii wide
		$ = "DownloadUpdate" ascii wide
		$ = "EndpointConnection" ascii wide
		$ = "Extensions" ascii wide
		$ = "FileCopier" ascii wide
		$ = "FileScanner" ascii wide
		$ = "FileScannerArg" ascii wide
		$ = "FileScanning" ascii wide
		$ = "FileSearcher" ascii wide
		$ = "FileZilla" ascii wide
		$ = "FullInfoSender" ascii wide
		$ = "GameLauncher" ascii wide
		$ = "GdiHelper" ascii wide
		$ = "GeoInfo" ascii wide
		$ = "GeoPlugin" ascii wide
		$ = "HardwareType" ascii wide
		$ = "IContract" ascii wide
		$ = "ITaskProcessor" ascii wide
		$ = "IdentitySenderBase" ascii wide
		$ = "LocalState" ascii wide
		$ = "LocatorAPI" ascii wide
		$ = "NativeHelper" ascii wide
		$ = "NordApp" ascii wide
		$ = "OpenUpdate" ascii wide
		$ = "OpenVPN" ascii wide
		$ = "OsCrypt" ascii wide
		$ = "ParsSt" ascii wide
		$ = "PartsSender" ascii wide
		$ = "RecordHeaderField" ascii wide
		$ = "ScanDetails" ascii wide
		$ = "ScanResult" ascii wide
		$ = "ScannedCookie" ascii wide
		$ = "ScannedFile" ascii wide
		$ = "ScanningArgs" ascii wide
		$ = "SenderFactory" ascii wide
		$ = "SqliteMasterEntry" ascii wide
		$ = "StringDecrypt" ascii wide
		$ = "SystemHardware" ascii wide
		$ = "SystemInfoHelper" ascii wide
		$ = "TableEntry" ascii wide
		$ = "TaskResolver" ascii wide
		$ = "UpdateAction" ascii wide
		$ = "UpdateTask" ascii wide
		$ = "WalletConfig" ascii wide

	condition:
		45 of them
}
