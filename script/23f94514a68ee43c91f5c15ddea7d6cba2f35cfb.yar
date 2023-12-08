rule Msfpayloads_msf_3
{
	meta:
		description = "Metasploit Payloads - file msf.psh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
		$s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
		$s3 = ".func]::VirtualAlloc(0,"
		$s4 = ".func+AllocationType]::Reserve -bOr [" ascii
		$s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
		$s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
		$s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
		$s8 = ".func]::CreateThread(0,0,$" fullword ascii
		$s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
		$s10 = "= [System.Convert]::FromBase64String(\"/" ascii
		$s11 = "{ $global:result = 3; return }" fullword ascii

	condition:
		4 of them
}
