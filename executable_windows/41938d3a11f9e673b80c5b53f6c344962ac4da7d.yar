import "pe"
import "math"

rule mimilove
{
	meta:
		description = "Detect the risk of Malware Mimikatz Rule 14"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "$http://blog.gentilkiwi.com/mimikatz 0" fullword ascii
		$s2 = "mimilove.exe" fullword wide
		$s3 = " '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)" fullword wide
		$s4 = "ERROR wmain ; OpenProcess (0x%08x)" fullword wide
		$s5 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_LOGON_SESSION_TABLE_50 (0x%08x)" fullword wide
		$s6 = "ERROR mimilove_lsasrv ; LogonSessionTable is NULL" fullword wide
		$s7 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KERB_HASHPASSWORD_5 (0x%08x)" fullword wide
		$s8 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KIWI_KERBEROS_LOGON_SESSION_50 (0x%08x)" fullword wide
		$s9 = "ERROR mimilove_kerberos ; KerbLogonSessionList is NULL" fullword wide
		$s10 = "ERROR mimilove_kerberos ; kull_m_memory_copy / KIWI_KERBEROS_KEYS_LIST_5 (0x%08x)" fullword wide
		$s11 = "ERROR kull_m_kernel_ioctl_handle ; DeviceIoControl (0x%08x) : 0x%08x" fullword wide
		$s12 = "UndefinedLogonType" fullword wide
		$s13 = "ERROR wmain ; GetVersionEx (0x%08x)" fullword wide
		$s14 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_PRIMARY_CREDENTIALS (0x%08x)" fullword wide
		$s15 = "ERROR mimilove_lsasrv ; kull_m_memory_copy / KIWI_MSV1_0_CREDENTIALS (0x%08x)" fullword wide
		$s16 = "KERBEROS Credentials (no tickets, sorry)" fullword wide
		$s17 = "Copyright (c) 2007 - 2021 gentilkiwi (Benjamin DELPY)" fullword wide
		$s18 = "benjamin@gentilkiwi.com0" fullword ascii
		$s19 = " * Username : %wZ" fullword wide
		$s20 = "http://subca.ocsp-certum.com01" fullword ascii
		$op0 = { 89 45 cc 6a 34 8d 45 cc 50 8d 45 c4 8d 4d 80 50 }
		$op1 = { 89 45 b8 c7 45 bc f7 ff ff ff 89 5d d4 89 5d f4 }
		$op2 = { 89 45 d4 c7 45 d8 f8 ff ff ff 89 7d f0 89 7d f4 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (8 of them and all of ($op*))
}
