rule HKTL_Nishang_PS1_Invoke_PowerShellTcpOneLine
{
	meta:
		description = "Detects PowerShell Oneliner in Nishang's repository"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
		date = "2021-03-03"
		hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "=([text.encoding]::ASCII).GetBytes((iex $" ascii wide
		$s2 = ".GetStream();[byte[]]$" ascii wide
		$s3 = "New-Object Net.Sockets.TCPClient('" ascii wide

	condition:
		all of them
}
