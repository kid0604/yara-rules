import "hash"
import "pe"

rule Sodinokibi_Loader
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 1"
		maltype = "Ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "function Invoke-" nocase
		$string2 = "$ForceASLR" nocase
		$string3 = "$DoNotZeroMZ" nocase
		$string4 = "$RemoteScriptBlock" nocase
		$string5 = "$TypeBuilder" nocase
		$string6 = "$Win32Constants" nocase
		$string7 = "$OpenProcess" nocase
		$string8 = "$WaitForSingleObject" nocase
		$string9 = "$WriteProcessMemory" nocase
		$string10 = "$ReadProcessMemory" nocase
		$string11 = "$CreateRemoteThread" nocase
		$string12 = "$OpenThreadToken" nocase
		$string13 = "$AdjustTokenPrivileges" nocase
		$string14 = "$LookupPrivilegeValue" nocase
		$string15 = "$ImpersonateSelf" nocase
		$string16 = "-SignedIntAsUnsigned" nocase
		$string17 = "Get-Win32Types" nocase
		$string18 = "Get-Win32Functions" nocase
		$string19 = "Write-BytesToMemory" nocase
		$string20 = "Get-ProcAddress" nocase
		$string21 = "Enable-SeDebugPrivilege" nocase
		$string22 = "Get-ImageNtHeaders" nocase
		$string23 = "Get-PEBasicInfo" nocase
		$string24 = "Get-PEDetailedInfo" nocase
		$string25 = "Import-DllInRemoteProcess" nocase
		$string26 = "Get-RemoteProcAddress" nocase
		$string27 = "Update-MemoryAddresses" nocase
		$string28 = "Import-DllImports" nocase
		$string29 = "Get-VirtualProtectValue" nocase
		$string30 = "Update-MemoryProtectionFlags" nocase
		$string31 = "Update-ExeFunctions" nocase
		$string32 = "Copy-ArrayOfMemAddresses" nocase
		$string33 = "Get-MemoryProcAddress" nocase
		$string34 = "Invoke-MemoryLoadLibrary" nocase
		$string35 = "Invoke-MemoryFreeLibrary" nocase
		$string36 = "$PEBytes32" nocase
		$string37 = "TVqQAA"
		$string38 = "FromBase64String" nocase

	condition:
		uint16(0)==0x5a4d and 30 of ($string*)
}
