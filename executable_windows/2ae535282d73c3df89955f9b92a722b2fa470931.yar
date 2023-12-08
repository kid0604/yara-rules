import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_DeleteWinDefednerQuarantineFiles
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding anti-forensic artifcats of deletiing Windows defender quarantine files"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "rmdir C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Entries /S" ascii wide nocase
		$s2 = "rmdir C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Resources /S" ascii wide nocase
		$s3 = "rmdir C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\ResourceData /S" ascii wide nocase
		$r1 = "rmdir" ascii wide nocase
		$p1 = "Microsoft\\Windows Defender\\Quarantine\\Entries /S" ascii wide nocase
		$p2 = "Microsoft\\Windows Defender\\Quarantine\\Resources /S" ascii wide nocase
		$p3 = "Microsoft\\Windows Defender\\Quarantine\\ResourceData /S" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or (1 of ($r*) and 2 of ($p*)))
}
