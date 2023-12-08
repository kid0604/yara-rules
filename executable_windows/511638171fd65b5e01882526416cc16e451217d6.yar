import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Undocumented_WinAPI_Kerberos
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing undocumented kerberos Windows APIs and obsereved in malware"
		os = "windows"
		filetype = "executable"

	strings:
		$kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
		$kdc2 = "KerbHashPasswordEx3" ascii wide nocase
		$kdc3 = "KerbFreeKey" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of ($kdc*)
}
