import "pe"

rule unlocker_alt_1
{
	meta:
		description = "mal - file unlocker.exe"
		author = "TheDFIRReport"
		date = "2021-11-29"
		hash1 = "09d7fcbf95e66b242ff5d7bc76e4d2c912462c8c344cb2b90070a38d27aaef53"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
		$s2 = "(Symantec SHA256 TimeStamping Signer - G20" fullword ascii
		$s3 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii
		$s4 = "(Symantec SHA256 TimeStamping Signer - G2" fullword ascii
		$s5 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
		$s6 = "Prevents the user from cancelling during the installation process." fullword wide
		$s7 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
		$s8 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
		$s9 = "The Setup program accepts optional command line parameters." fullword wide
		$s10 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide
		$s11 = "Overrides the default component settings." fullword wide
		$s12 = "/MERGETASKS=\"comma separated list of task names\"" fullword wide
		$s13 = "/PASSWORD=password" fullword wide
		$s14 = "Specifies the password to use." fullword wide
		$s15 = "yyyyvvvvvvvvvxxw" fullword ascii
		$s16 = "yyyyyyrrrsy" fullword ascii
		$s17 = "            processorArchitecture=\"x86\"" fullword ascii
		$s18 = "    processorArchitecture=\"x86\"" fullword ascii
		$s19 = "Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requ" wide
		$s20 = "/DIR=\"x:\\dirname\"" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <7000KB and all of them
}
