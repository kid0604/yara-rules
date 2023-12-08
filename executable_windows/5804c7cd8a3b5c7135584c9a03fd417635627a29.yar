import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_USNDeleteJournal
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing anti-forensic artifcats of deletiing USN change journal. Observed in ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$cmd1 = "fsutil.exe" ascii wide nocase
		$s1 = "usn deletejournal /D C:" ascii wide nocase
		$s2 = "fsutil.exe usn deletejournal" ascii wide nocase
		$s3 = "fsutil usn deletejournal" ascii wide nocase
		$s4 = "fsutil file setZeroData offset=0" ascii wide nocase
		$ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
		$ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
		$ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
		$ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide

	condition:
		uint16(0)==0x5a4d and ( not any of ($ne*) and ((1 of ($cmd*) and 1 of ($s*)) or 1 of ($s*)))
}
