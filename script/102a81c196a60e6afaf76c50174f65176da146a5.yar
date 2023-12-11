rule APT_MAL_CN_Wocao_xserver_powershell_dropper
{
	meta:
		description = "Strings from the PowerShell dropper of XServer"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows"
		filetype = "script"

	strings:
		$encfile = "New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($encfile)"

	condition:
		all of them
}
