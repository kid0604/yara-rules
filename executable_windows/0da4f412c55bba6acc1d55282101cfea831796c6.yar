rule IndiaAlfa_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects the presence of specific file names related to HwpFilePathCheck.dll, AdobeArm.exe, and OpenDocument"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "HwpFilePathCheck.dll"
		$ = "AdobeArm.exe"
		$ = "OpenDocument"

	condition:
		2 of them
}
