import "pe"

rule MALWARE_Win_Zeppelin
{
	meta:
		author = "ditekSHen"
		description = "Detects Zeppelin (Delphi) ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "TUnlockAndEncrypt" ascii
		$s2 = "TExcludeFiles" ascii
		$s3 = "TExcludeFolders" ascii
		$s4 = "TDrivesAndShares" ascii
		$s5 = "TTaskKiller" ascii
		$x1 = "!!! D !!!" ascii
		$x2 = "!!! LOCALPUBKEY !!!" ascii
		$x3 = "!!! ENCLOCALPRIVKEY !!!" ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or all of ($x*) or (2 of ($x*) and 2 of ($s*)))
}
