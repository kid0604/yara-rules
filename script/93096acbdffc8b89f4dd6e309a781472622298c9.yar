rule Empire_lib_modules_trollsploit_message
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii
		$s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii
		$s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii
		$s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii

	condition:
		filesize <10KB and 3 of them
}
