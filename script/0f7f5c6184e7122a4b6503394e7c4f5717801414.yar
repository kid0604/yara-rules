rule SUSP_PowerShell_String_K32_RemProcess
{
	meta:
		description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nccgroup/redsnarf"
		date = "2018-03-31"
		hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
		hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Throw \"Unable to allocate memory in the remote process for shellcode\"" fullword ascii
		$x2 = "$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke(\"kernel32.dll\")" fullword ascii
		$s3 = "$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants." ascii
		$s7 = "if ($RemoteProcHandle -eq [IntPtr]::Zero)" fullword ascii
		$s8 = "if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))" fullword ascii
		$s9 = "$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, " ascii
		$s15 = "$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null" fullword ascii

	condition:
		uint16(0)==0x7566 and filesize <6000KB and 1 of them
}
