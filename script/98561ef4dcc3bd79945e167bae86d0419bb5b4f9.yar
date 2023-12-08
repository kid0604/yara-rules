import "pe"

rule MALWARE_Win_DLAgent10
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell.exe" ascii wide nocase
		$s2 = ".DownloadFile(" ascii wide nocase
		$s3 = "_UseShellExecute" ascii wide nocase
		$s4 = "_CreateNoWindow" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
