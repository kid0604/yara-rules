import "pe"

rule MALWARE_Win_UNK03
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii
		$s2 = "rundll32.exe C:\\Windows\\System32\\shimgvw.dll,ImageView_Fullscreen %s" ascii
		$s3 = "%s.jpg" ascii
		$s4 = "%s\\sz.txt" ascii
		$s5 = "ChromeSecsv9867%d7.exe" ascii
		$s6 = "%s\\appl%c.jpg" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
