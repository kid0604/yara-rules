rule HawkEye_Keylogger_Feb18_1
{
	meta:
		description = "Semiautomatically generated YARA rule"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
		date = "2018-02-12"
		modified = "2023-01-06"
		score = 90
		hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UploadReportLogin.asmx" fullword wide
		$s2 = "tmp.exe" fullword wide
		$s3 = "%appdata%\\" wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
