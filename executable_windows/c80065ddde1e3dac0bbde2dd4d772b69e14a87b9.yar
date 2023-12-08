import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_Sandbox_Evasion_FilesComb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing specific set of files observed in sandob anti-evation, and Emotet"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\take_screenshot.ps1" ascii wide nocase
		$s2 = "c:\\loaddll.exe" ascii wide nocase
		$s3 = "c:\\email.doc" ascii wide nocase
		$s4 = "c:\\email.htm" ascii wide nocase
		$s5 = "c:\\123\\email.doc" ascii wide nocase
		$s6 = "c:\\123\\email.docx" ascii wide nocase
		$s7 = "c:\\a\\foobar.bmp" ascii wide nocase
		$s8 = "c:\\a\\foobar.doc" ascii wide nocase
		$s9 = "c:\\a\\foobar.gif" ascii wide nocase
		$s10 = "c:\\symbols\\aagmmc.pdb" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 6 of them
}
