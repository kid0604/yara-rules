rule Empire_lib_modules_credentials_mimikatz_pth
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
		$s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii

	condition:
		filesize <12KB and all of them
}
