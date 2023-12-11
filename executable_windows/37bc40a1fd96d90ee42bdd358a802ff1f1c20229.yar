import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCMD
{
	meta:
		author = "ditekSHen"
		description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
		$s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
		$s3 = "CMSTPBypass" fullword ascii
		$s4 = "CommandToExecute" fullword ascii
		$s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
		$s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
