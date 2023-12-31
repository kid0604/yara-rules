rule malware_macos_bella
{
	meta:
		description = "Bella is a pure python post-exploitation data mining tool & remote administration tool for macOS."
		reference = "https://github.com/Trietptm-on-Security/Bella"
		author = "@mimeframe"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = "Verified! [2FV Enabled] Account ->" wide ascii
		$a2 = "There is no root shell to perform this command. See [rooter] manual entry." wide ascii
		$a3 = "Attempt to escalate Bella to root through a variety of attack vectors." wide ascii
		$a4 = "BELLA IS NOW RUNNING. CONNECT TO BELLA FROM THE CONTROL CENTER." wide ascii
		$b1 = "user_pass_phish" fullword wide ascii
		$b2 = "bella_info" fullword wide ascii
		$b3 = "get_root" fullword wide ascii
		$c1 = "Please specify a bella server." wide ascii
		$c2 = "What port should Bella connect on [Default is 4545]:" wide ascii

	condition:
		any of ($a*) or all of ($b*) or all of ($c*)
}
