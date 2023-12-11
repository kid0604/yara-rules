import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_DeleteRecentItems
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding anti-forensic artifcats of deletiing Windows Recent Items"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "del C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf" ascii wide nocase
		$s2 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\*" ascii wide nocase
		$s3 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*" ascii wide nocase
		$s4 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 2 of them
}
