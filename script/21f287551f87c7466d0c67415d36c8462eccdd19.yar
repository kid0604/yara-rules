rule Msfpayloads_msf_ref
{
	meta:
		description = "Metasploit Payloads - file msf-ref.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "4ec95724b4c2b6cb57d2c63332a1dd6d4a0101707f42e3d693c9aab19f6c9f87"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "kernel32.dll WaitForSingleObject)," ascii
		$s2 = "= ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')" ascii
		$s3 = "GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object" ascii
		$s4 = ".DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual'," ascii
		$s5 = "= [System.Convert]::FromBase64String(" ascii
		$s6 = "[Parameter(Position = 0, Mandatory = $True)] [Type[]]" fullword ascii
		$s7 = "DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard," ascii

	condition:
		5 of them
}
