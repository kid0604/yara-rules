rule INDICATOR_TOOL_AVBypass_AVIator
{
	meta:
		author = "ditekSHen"
		description = "Detects AVIator, which is a backdoor generator utility, which uses cryptographic and injection techniques in order to bypass AV detection. This was observed to bypass Win.Trojan.AZorult. This rule works for binaries and memory."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "msfvenom -p windows/meterpreter" ascii wide
		$s2 = "payloadBox.Text" ascii wide
		$s3 = "APCInjectionCheckBox" ascii wide
		$s4 = "Thread Hijacking (Shellcode Arch: x86, OS Arch: x86)" ascii wide
		$s5 = "injectExistingApp.Text" ascii wide
		$s6 = "Stable execution but can be traced by most AVs" ascii wide
		$s7 = "AV/\\tor" ascii wide
		$s8 = "AvIator.Properties.Resources" ascii wide
		$s9 = "Select injection technique" ascii wide
		$s10 = "threadHijacking_option" ascii wide
		$pwsh1 = "Convert.ToByte(Payload_Encrypted_Without_delimiterChar[" ascii wide
		$pwsh2 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" ascii wide
		$pwsh3 = "IntPtr RtlAdjustPrivilege(" ascii wide
		$pwsh4 = /InjectShellcode\.(THREADENTRY32|CONTEXT64|WriteProcessMemory\(|CloseHandle\(|CONTEXT_FLAGS|CONTEXT\(\);|Thread32Next\()/ ascii wide
		$pwsh5 = "= Payload_Encrypted.Split(',');" ascii wide
		$pwsh6 = "namespace NativePayload_Reverse_tcp" ascii wide
		$pwsh7 = "byte[] Finall_Payload = Decrypt(KEY, _X_to_Bytes);" ascii wide
		$pwsh8 = /ConstantsAndExtCalls\.(WriteProcessMemory\(|CreateRemoteThread\()/ ascii wide

	condition:
		( uint16(0)==0x5a4d and (3 of ($s*) or 2 of ($pwsh*))) or (3 of ($s*) or 2 of ($pwsh*))
}
